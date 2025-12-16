#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <time.h>
#define TLS_REEXPORTABLE 1
#define USE_TFM 1
#define TFM_DESC 1
#define TLS_REEXPORTABLE 1
#define WITH_KTLS 1

#ifndef TCPOPT_MSS
#define TCPOPT_MSS 2
#endif

#ifndef TCPOPT_WINDOW
#define TCPOPT_WINDOW 3
#endif

#ifndef TCPOPT_SACK_PERM
#define TCPOPT_SACK_PERM 4
#endif

#ifndef TCPOPT_TIMESTAMP
#define TCPOPT_TIMESTAMP 8
#endif

#ifdef DO_SKWALL
#include <bpf/bpf.h>
#include "skwall.h"
#endif /* DO_SKWALL */

static inline void
ast(int cond, char *func, char *msg)
{
	if (cond)
		return;
	if (func)
		perror(func);
	if (msg)
		printf("%s\n", msg);
	exit(1);
}

struct tcp_info_sub {
	uint8_t tcpi_state;
	uint8_t tcpi_ca_state;
	uint8_t tcpi_retransmits;
	uint8_t tcpi_probes;
	uint8_t tcpi_backoff;
	uint8_t tcpi_options;
	uint8_t tcpi_snd_wscale : 4;
	uint8_t tcpi_rcv_wscale : 4;
} info;

#ifdef DO_REPAIR
static int
restore_queue(int fd, int q, const uint8_t *buf, uint32_t len, int need_repair)
{
	int ret,  max_chunk = len, off = 0;

	if (need_repair)
		ast(setsockopt(fd, IPPROTO_TCP, TCP_REPAIR_QUEUE, &q,
				sizeof(q)) == 0, "setsockopt", NULL);
	do {
		int chunk = len > max_chunk ? max_chunk : len;
		ret = send(fd, buf + off, chunk, 0);
		if (ret <= 0) {
			if (max_chunk > 1024 /* see tcp_export.cpp */) {
				max_chunk >>= 1;
				continue;
			}
			return errno;
		}
		off += ret;
		len -= ret;
	} while (len);
	return 0;
}
#endif /* DO_REPAIR */

static char *HTTPHDR = (char *)"HTTP/1.1 200 OK\r\n"
		 "Connection: keep-alive\r\n"
		 "Server: Apache/2.2.800\r\n"
		 "Content-Length: 5\r\n\r\n"
		 "hoge";

static void
epoll_add(int epfd, int fd)
{
	struct epoll_event ev;
	bzero(&ev, sizeof(ev));
	ev.data.fd = fd;
	ev.events = EPOLLIN | EPOLLERR;
	ast(epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == 0, "epoll_ctl", NULL);
}

static void
reuseaddr(int fd)
{
	ast(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int))
		       	== 0, "setsockopt", NULL);
	ast(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int))
			== 0, "setsockopt", NULL);
}

int
main()
{
	struct sockaddr_in sin = {.sin_family = AF_INET};
	socklen_t slen;
	int so = socket(AF_INET, SOCK_STREAM , IPPROTO_TCP);
	int epfd;
	struct epoll_event evs[1024];
#ifdef DO_SKWALL
	int map_fd;
	struct skwall skw = {.on = 1};
#endif /* DO_SKWALL */

	ast(so > 0, "socket", NULL);
	
	sin.sin_port = htons(50000);
	sin.sin_addr.s_addr = INADDR_ANY;
	//inet_pton(AF_INET, "192.168.122.185", &sin.sin_addr);

#ifdef DO_SKWALL
#define SKWALLMAP	"/sys/fs/bpf/skwall/skwall_map"
	/* open map */
	map_fd = bpf_obj_get(SKWALLMAP);
	if (map_fd < 0) {
		perror("bpf_obj_get");
		return 0;
	}
#endif
	
	reuseaddr(so);
	ast(bind(so, (struct sockaddr *)&sin, sizeof(sin)) == 0, "bind", NULL);
	ast(listen(so, 5) == 0, "listen", NULL);
	
	ast((epfd = epoll_create(1024)) > 0, "epoll_create", NULL);
	epoll_add(epfd, so);
	
	for (;;) {
		int n = epoll_wait(epfd, evs, 1024, 2000), i;

		ast(n >= 0, "epoll_wait", NULL);

		for (i = 0; i < n; i++) {
			ssize_t len;
			int fd = evs[i].data.fd;
			char buf[1024];
#ifdef DO_REPAIR
			struct sockaddr_in sin2;
			int sndq_len, unsndq_len, rcvq_len;
                        uint32_t mss, ts;
                        socklen_t olen_mss = sizeof(mss);
                        socklen_t olen_ts = sizeof(ts);
                        struct tcp_repair_window window;
			uint32_t seqno_send, seqno_recv;
			const int qid_snd = TCP_SEND_QUEUE;
			const int qid_rcv = TCP_RECV_QUEUE;
			socklen_t ulen;
			char *sndbuf = NULL, *rcvbuf = NULL;
			const int peek = MSG_PEEK | MSG_DONTWAIT;
			struct tcp_repair_opt opts[4];
			const int dopt = -1;
#endif /* DO_REPAIR */

			if (evs[i].events & EPOLLERR) {
				close(fd);
				continue;
			}

			slen = sizeof(sin);
			if (fd == so) {
				int newfd = accept(so, (struct sockaddr *)&sin,
						&slen);
				ast(newfd > 0, "accept", NULL);
				reuseaddr(newfd);
				epoll_add(epfd, newfd);
				continue;
			}
			len = read(fd, buf, sizeof(buf));
			ast(len >= 0, "read", NULL);
			if (len == 0) {
				close(fd);
				continue;
			}
//sleep(1);
#ifdef DO_REPAIR
#ifdef DO_SKWALL
			skw.on = 1;
			ast(bpf_map_update_elem(map_fd, (void *)&fd, &skw,
				BPF_ANY) == 0,	"bpf_map_update_elem", NULL);
sleep(1);
#endif /* DO_SKWALL */
			ast(setsockopt(fd, IPPROTO_TCP, TCP_REPAIR, &(int){1},
				sizeof(int)) == 0, "setsockopt", NULL);
			slen = sizeof(info);
			ast(getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info,
				&slen)	== 0, "getsockopt", NULL);
			ast(info.tcpi_state == TCP_ESTABLISHED,
					NULL, "not established");
			ast(ioctl(fd, SIOCOUTQ, &sndq_len) == 0, "ioctl", NULL);
			ast(ioctl(fd, SIOCOUTQNSD, &unsndq_len) == 0,
					"ioctl", NULL);
			ast(ioctl(fd, SIOCINQ, &rcvq_len) == 0, "ioctl", NULL);

			ast(getsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &mss,
					&olen_mss) == 0, "getsockopt", NULL);
			ast(getsockopt(fd, IPPROTO_TCP, TCP_TIMESTAMP, &ts,
					&olen_ts) == 0, "getsockopt", NULL);
			/* window scale in info */

			slen = sizeof(window);
			ast(getsockopt(fd, IPPROTO_TCP, TCP_REPAIR_WINDOW,
					&window, &slen) == 0,
					"getsockopt", "REPAIR_WINDOW");

			bzero(&sin, sizeof(sin));
			sin.sin_family = AF_INET;
			slen = sizeof(sin);
			ast(getsockname(fd, (struct sockaddr *)&sin, &slen)
				       	== 0, "getsockname", NULL);
			bzero(&sin2, sizeof(sin2));
			sin2.sin_family = AF_INET;
			slen = sizeof(sin2);
			ast(getpeername(fd, (struct sockaddr *)&sin2, &slen)
					== 0, "getpeername", NULL);


			ast(setsockopt(fd, IPPROTO_TCP, TCP_REPAIR_QUEUE, 
					&qid_snd, sizeof(qid_snd)) == 0,
					"setsockopt", NULL);
			slen = sizeof(seqno_send);
			ast(getsockopt(fd, IPPROTO_TCP, TCP_QUEUE_SEQ, 
					&seqno_send, &slen)
					== 0, "getsockopt", NULL);
			if (sndq_len) {
				ast((sndbuf = calloc(1, sndq_len + 1)) != NULL,
							"calloc", NULL);
				ast(recv(fd, sndbuf, sndq_len + 1, peek)
					== sndq_len, "recv", NULL);
			}

			ast(setsockopt(fd, IPPROTO_TCP, TCP_REPAIR_QUEUE, 
					&qid_rcv, sizeof(qid_rcv)) == 0,
					"setsockopt", NULL);
			slen = sizeof(seqno_recv);
			ast(getsockopt(fd, IPPROTO_TCP, TCP_QUEUE_SEQ, 
					&seqno_recv, &slen)
					== 0, "getsockopt", NULL);
			if (rcvq_len) {
				ast((rcvbuf = calloc(1, rcvq_len + 1)) != NULL,
							"calloc", NULL);
				ast(recv(fd, rcvbuf, rcvq_len + 1, peek)
					== rcvq_len, "recv", NULL);
			}

			ast(epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL)
				       	== 0, "epoll_ctl", NULL);
			close(fd);

			ast((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))
					> 0, "socket", NULL);
			reuseaddr(fd);

#ifdef DO_SKWALL
			skw.on = 1;
			ast(bpf_map_update_elem(map_fd, (void *)&fd, &skw,
				BPF_ANY) == 0,	"bpf_map_update_elem", NULL);
#endif /* DO_SKWALL */
			ast(setsockopt(fd, IPPROTO_TCP, TCP_REPAIR, &(int){1},
				sizeof(int)) == 0, "setsockopt", NULL);

			ast(setsockopt(fd, IPPROTO_TCP, TCP_REPAIR_QUEUE,
				&qid_snd, sizeof(qid_snd)) == 0,
				"setsockopt", NULL);
			ast(setsockopt(fd, IPPROTO_TCP, TCP_QUEUE_SEQ,
				&seqno_send, sizeof(seqno_send)) == 0,
				"setsockopt", NULL);

			ast(setsockopt(fd, IPPROTO_TCP, TCP_REPAIR_QUEUE,
				&qid_rcv, sizeof(qid_rcv)) == 0,
				"setsockopt", NULL);
			ast(setsockopt(fd, IPPROTO_TCP, TCP_QUEUE_SEQ,
				&seqno_recv, sizeof(seqno_recv)) == 0,
				"setsockopt", NULL);

			ast(bind(fd, (struct sockaddr *)&sin, sizeof(sin))
				       	== 0, "bind", "post repair");
			ast(connect(fd, (struct sockaddr *)&sin2, sizeof(sin2))
					== 0, "connect", NULL);

			ulen = unsndq_len;
			len = sndq_len - ulen;
			if (len) {
				ast(restore_queue(fd, TCP_SEND_QUEUE,
					(const uint8_t *)sndbuf, len, 1)
					== 0, NULL, "restore_queue");
			}
			if (ulen) {
				ast(setsockopt(fd, IPPROTO_TCP, TCP_REPAIR,
						&dopt, sizeof(dopt))
						== 0, "setsockopt", NULL);
				ast(restore_queue(fd, TCP_SEND_QUEUE,
					(const uint8_t *)sndbuf + len, ulen, 0)
					== 0, NULL, "restore_queue");
				ast(setsockopt(fd, IPPROTO_TCP, TCP_REPAIR,
						&(int){1}, sizeof(int)) == 0,
						"setsockopt", NULL);

			}
			if (rcvq_len > 0) {
				ast(restore_queue(fd, TCP_RECV_QUEUE,
					(const uint8_t *)rcvbuf, rcvq_len, 1)
					== 0, NULL, "restore_queue");

			}

			bzero(opts, sizeof(opts));
                        opts[0].opt_code = TCPOPT_SACK_PERM;
                        opts[0].opt_val = 0;
                        opts[1].opt_code = TCPOPT_WINDOW;
                        opts[1].opt_val = info.tcpi_snd_wscale +
				(info.tcpi_rcv_wscale << 16);
                        opts[2].opt_code = TCPOPT_TIMESTAMP;
                        opts[2].opt_val = 0;
                        opts[3].opt_code = TCPOPT_MSS;
                        opts[3].opt_val = mss;
			ast(setsockopt(fd, IPPROTO_TCP, TCP_REPAIR_OPTIONS,
					opts, sizeof(struct tcp_repair_opt) * 4)
				       	== 0, "setsockopt", "REPAIR_OPTIONS");
			ast(setsockopt(fd, IPPROTO_TCP, TCP_TIMESTAMP, &ts,
					sizeof(ts)) == 0, "setsockopt", NULL);
			ast(setsockopt(fd, IPPROTO_TCP, TCP_REPAIR_WINDOW,
					&window, sizeof(window)) == 0,
					"setsockopt", NULL);

			ast(setsockopt(fd, IPPROTO_TCP, TCP_REPAIR, &dopt,
				sizeof(dopt)) == 0, "setsockopt", NULL);
#ifdef DO_SKWALL
			skw.on = 0;
			ast(bpf_map_update_elem(map_fd, (void *)&fd, &skw,
				BPF_ANY) == 0,	"bpf_map_update_elem", NULL);
#endif /* DO_SKWALL */

			epoll_add(epfd, fd);
#endif /* DO_REPAIR */

			len = write(fd, HTTPHDR, strlen(HTTPHDR)+1);
			ast(len > 0, "write", NULL);
		}
	}
	return 0;
}
