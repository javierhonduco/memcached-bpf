// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 10);
	__type(key, __u32);
	__type(value, __u64);
} sockhash SEC(".maps");


struct storage_value {
	char contents[100];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key, __u64);
	__type(value, struct storage_value);
} storage SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key, __u64);
	__type(value, int);
} clients SEC(".maps");


// Port we listen on. Set on the driver program
const volatile int listening_port = 0;


// Size of the packet to parse
SEC("sk_skb/stream_parser")
int _prog_parser(struct __sk_buff *skb)
{
	bpf_printk("parser\n");
	return skb->len;
}

// What should we do to the package? Here we can examine
// and change its contents, as well as decide if we are
// dropping the package or not (SK_DROP=0, SK_PASS=1)
SEC("sk_skb/stream_verdict")
int _prog_verdict(struct __sk_buff *skb)
{
	bpf_printk("veredict\n");

	__u64 key = (skb->remote_ip4 << 32) | skb->remote_port;
	struct client *client = bpf_map_lookup_elem(&clients, &key);
	if (!client) {
		bpf_printk("can't find client %u\n", key);
		return SK_DROP;
	}

	bpf_skb_pull_data(skb, skb->len);

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	char *c = data;

	bpf_printk("== raw data: (%s)\n", c);

	// Parse the memcache commands. We reuse the socket we are reading
	// so we need to do the math to see whether we need extra space
	// for the response. This can be done with `bpf_skb_adjust_room`,
	// but even though my kernel supports it, the verifier say that
	// it does not exist? Until that's not sorted out this is useless :(
	//
	// Ideas:
	// 	- Right now this is meant as a memcache clone, but we could
	//	instead act as a cache on top of memcached. This way we could
	//	focus on some part of the keyspace this program could perform
	//	well at and let memcache handle trickier data that may be prone
	//	to memory fragmentation
	//  - Have different "slab" sizes
	//  - Faster command parsing using bigger types

	int min_command_length = 5; // len("get a") = 5

	// My kernel can't find this helper??
	// bpf_skb_adjust_room(skb, 10, 0, -1);


 	if (data + min_command_length > data_end) {
			bpf_printk("command is too short\n");
			return SK_DROP;
	}

	// Handle get
	if (c[0] == 'g' && c[1] == 'e' && c[2] == 't' && c[3] == ' ') {
		bpf_printk("~ get: %s\n", (char *) c+4);
		__builtin_memcpy(data,
						(void *)"val\r\nEND\r\n",
						5);
	// Handle set
	} else if (c[0] == 's' && c[1] == 'e' && c[2] == 't' && c[3] == ' ') {

		bpf_printk("~ set: %s\r\n", (char *) c+4);
		// store data here
		// bpf_map_update_elem(&storage, &key, &nc, 0);
		__builtin_memcpy(data,
					(void *)"\r\n",
					5);
	// Handle delete
	} else if (c[0] == 'd' && c[1] == 'e' && c[2] == 'l' && c[3] == ' ') {

		bpf_printk("~ del: %s\n", (char *) c+4);
		__builtin_memcpy(data,
					(void *)"DEL!",
					5);
	// Not implemented
	} else {
		bpf_printk("! command not implemented\n", c);
		return SK_DROP;
	}


	int ret = bpf_sk_redirect_hash(skb, &sockhash, &key, 0);
	bpf_printk("- call bpf_sk_redirect_hash ret=%d\n", ret);
	return ret;
}


// Socket lifecycle changes, such as TCP connection creation,
// closing, etc. We do the mapping of client => socket here
SEC("sockops")
int _sock_ops(struct bpf_sock_ops *ops)
{
	bpf_printk("sockops\n");

	if (ops->local_port != listening_port) {
		return 0;
	}

	__u64 key = (ops->remote_ip4 << 32) | ops->remote_port;

	// Handle TCP_CLOSE
	if (ops->op  == BPF_SOCK_OPS_STATE_CB && ops->args[1] == 7) {
		bpf_printk("state change %u %u\n", ops->args[1], ops->args[2]);
		bpf_map_delete_elem(&clients, &key);
		return 0;
	}

	// Handle connection stablishment
	if (ops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB ||
	    ops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
		int zero = 0;
		bpf_map_update_elem(&clients, &key, &zero, 0);
		bpf_sock_ops_cb_flags_set(ops,
					  ops->bpf_sock_ops_cb_flags |
						  BPF_SOCK_OPS_STATE_CB_FLAG);


		bpf_sock_hash_update(ops, &sockhash, &key, 0);
	}

	return 0;
}



// Was just using this to make sure the BPF programs were getting
// loaded.

// SEC("tracepoint/syscalls/sys_enter_write")
// void bpf_sys_open(struct pt_regs *ctx) {
//	bpf_printk("sys_open pp\n");
//}

char LICENSE[] SEC("license") = "GPL";
