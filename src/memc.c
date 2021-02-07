#include <stdio.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <argp.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include "memc.skel.h"


#define port 1111
#define backlog 8192
#define epoll_events 8192

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

int main(int argc, char **argv)
{
	struct memc_bpf *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
	bump_memlock_rlimit();

	/* Open BPF application */
	skel = memc_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->listening_port = port;

	/* Load & verify BPF programs */
	err = memc_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/*
	err = memc_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	*/

	int cg_fd = open("/sys/fs/cgroup/unified", O_RDONLY);
	if (cg_fd < 0) {
		fprintf(stderr, "failed to open cg: %s\n",
			strerror(errno));
		return -1;
	}
	if (bpf_program__attach_cgroup(skel->progs._sock_ops, cg_fd) < 0){
		fprintf(stderr, "Could not open /sys/fs/cgroup/unified due to: %s\n",
					strerror(errno));
		//return -1;

	}

	int sockhash_fd = bpf_object__find_map_fd_by_name(skel->obj, "sockhash");
	if (sockhash_fd<0){
		fprintf(stderr, "Failed to find sockhash: %s\n",
			strerror(errno));
		return -1;
	}
	struct bpf_program *p = bpf_object__find_program_by_name(skel->obj, "_prog_parser");
	err = bpf_prog_attach(bpf_program__fd(p), sockhash_fd,
			      BPF_SK_SKB_STREAM_PARSER, 0);
	if (err < 0) {
		fprintf(stderr, "Ffailed to attac _prog_parser: %s\n",
			strerror(errno));
		return -1;
	}
	p = bpf_object__find_program_by_name(skel->obj, "_prog_verdict");
	err = bpf_prog_attach(bpf_program__fd(p), sockhash_fd,
			      BPF_SK_SKB_STREAM_VERDICT, 0);
	if (err < 0) {
		fprintf(stderr, "Failed to attach _prog_verdict: %s\n",
			strerror(errno));
		return -1;
	}

	int listen_fd = socket(AF_INET, SOCK_STREAM, 0);

	printf("Successfully started!\n");

	struct sockaddr sa;
	memset(&sa, 0, sizeof(sa));
	struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
	sin->sin_family = AF_INET;
	sin->sin_port = htons(port);
	inet_aton("0.0.0.0", &sin->sin_addr);

	err = bind(listen_fd, (struct sockaddr *)sin, sizeof(*sin));
	if (err < 0) {
		fprintf(stderr, "failed to bind: %s\n", strerror(errno));
		return 1;
	}

	err = listen(listen_fd, backlog);
	if (err < 0) {
		fprintf(stderr, "failed to listen: %s\n", strerror(errno));
		return 1;
	}

	int epfd = epoll_create(1);
	struct epoll_event ev;
	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = listen_fd;
	epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev);

	int i, nevent;
	struct epoll_event events[epoll_events];

	// From https://github.com/fujita/greeter-bpf
	for(;;) {
		nevent = epoll_wait(epfd, events, sizeof(events)/sizeof(events[0]), -1);
		for (i = 0; i < nevent; i++) {
			if (events[i].data.fd == listen_fd) {
				struct sockaddr_in ss;
				socklen_t ss_len = sizeof(struct sockaddr_in);
				int fd = accept(listen_fd, (struct sockaddr *)&ss, &ss_len);

				if (fd < 0) {
					continue;
				}

				printf("accepted %d %s %d\n", fd, inet_ntoa(ss.sin_addr), ntohs(ss.sin_port));
				struct epoll_event ev = {
					.events = EPOLLRDHUP | EPOLLET,
					.data.fd = fd,
				};
				epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
			} else {
				close(events[i].data.fd);
			}
		}
	}

cleanup:
	memc_bpf__destroy(skel);
	return -err;
}
