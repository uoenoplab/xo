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
#ifdef WITH_TLS
#ifndef LTM_DESC
#define LTM_DESC
#endif

#ifndef NO_SSL_COMPATIBLE_INTERFACE
#define NO_SSL_COMPATIBLE_INTERFACE
#endif

#ifndef TLS_REEXPORTABLE
#define TLS_REEXPORTABLE
#endif

#include "tlse.c"
#endif /* WITH_TLS */

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

double diff_timespec(const struct timespec *time1, const struct timespec *time0) {
        return (time1->tv_sec - time0->tv_sec) + (time1->tv_nsec - time0->tv_nsec) / 1000000000.0;
}
#define D(_fmt, ...)                                            \
        do {                                                    \
                struct timeval _t0;                             \
                gettimeofday(&_t0, NULL);                       \
                fprintf(stderr, "%03d.%06d %s [%d] " _fmt "", \
                    (int)(_t0.tv_sec % 1000), (int)_t0.tv_usec, \
                    __FUNCTION__, __LINE__, ##__VA_ARGS__);     \
        } while (0)

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

#ifdef WITH_TLS
static char identity_str[0xFF] = {0};

int read_from_file(const char *fname, void *buf, int max_len) {
    FILE *f = fopen(fname, "rb");
    if (f) {
        int size = fread(buf, 1, max_len - 1, f); 
        if (size > 0)
            ((unsigned char *)buf)[size] = 0;
        else
            ((unsigned char *)buf)[0] = 0;
        fclose(f);
        return size;
    }   
    return 0;
}

void load_keys(struct TLSContext *context, char *fname, char *priv_fname) {
    unsigned char buf[0xFFFF];
    unsigned char buf2[0xFFFF];
    int size = read_from_file(fname, buf, 0xFFFF);
    int size2 = read_from_file(priv_fname, buf2, 0xFFFF);
    if (size > 0) {
        if (context) {
            tls_load_certificates(context, buf, size);
            tls_load_private_key(context, buf2, size2);
            // tls_print_certificate(fname);
        }   
    }   
}

int send_pending(int clnt_sock, struct TLSContext *context) {
    unsigned int out_buffer_len = 0;
    const unsigned char *out_buffer = tls_get_write_buffer(context, &out_buffer_len);
    unsigned int out_buffer_index = 0;
    int send_res = 0;

    while ((out_buffer) && (out_buffer_len > 0)) {
        int res = send(clnt_sock, (char *)&out_buffer[out_buffer_index],
			out_buffer_len, MSG_DONTWAIT);
        if (res <= 0) {
            send_res = res;
            break;
        }
        out_buffer_len -= res;
        out_buffer_index += res;
    }
    tls_buffer_clear(context);
    return send_res;
}

int verify_signature(struct TLSContext *context, struct TLSCertificate **certificate_chain, int len) {
    if (len) {
        struct TLSCertificate *cert = certificate_chain[0];
        if (cert) {
            snprintf(identity_str, sizeof(identity_str), "%s, %s(%s) (issued by: %s)", cert->subject, cert->entity, cert->location, cert->issuer_entity);
            fprintf(stderr, "Verified: %s\n", identity_str);
        }
    }
    return no_error;
}

int handshake_reading(struct TLSContext *context, const void* buf, int len, int fd)
{
        unsigned char buf2[1024];

        if (tls_consume_stream(context, buf, len, verify_signature) < 0)
                printf("tls consume stream cannot receive message\n");
        /* consume leftover */
        while ((len = recv(fd, buf2, sizeof(buf2), MSG_DONTWAIT)) > 0)
        {
                if (tls_consume_stream(context, buf2, len, verify_signature) < 0)
                        fprintf(stderr, "Error in tls_consume_stream\n");
        }
        return 0;
}


#endif /* WITH_TLS */

static const char *HTTPHDR = (char *)"HTTP/1.1 200 OK\r\n"
		 "Connection: keep-alive\r\n"
		 "Server: Apache/2.2.800\r\n"
		 "Content-Length: 5\r\n\r\n"
		 "hoge";

static void
epoll_add(int epfd, int fd)
{
	struct epoll_event ev;//used for epoo_ctl()
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

#ifdef WITH_TLS
void print_tls_context(struct TLSContext *ctx) {
    printf("remote_random: ");
    for (int i = 0; i < TLS_CLIENT_RANDOM_SIZE; i++) {
        printf("%02x", ctx->remote_random[i]);
    }
    printf("\n");

    printf("local_random: ");
    for (int i = 0; i < TLS_SERVER_RANDOM_SIZE; i++) {
        printf("%02x", ctx->local_random[i]);
    }
    printf("\n");

    printf("session: ");
    for (int i = 0; i < ctx->session_size; i++) {
        printf("%02x", ctx->session[i]);
    }
    printf("\n");

    printf("session_size: %u\n", ctx->session_size);
    printf("cipher: %u\n", ctx->cipher);
    printf("version: %u\n", ctx->version);
    printf("is_server: %u\n", ctx->is_server);
    // ... print other fields ...

    printf("certificates_count: %u\n", ctx->certificates_count);
    printf("client_certificates_count: %u\n", ctx->client_certificates_count);
    printf("master_key_len: %u\n", ctx->master_key_len);
    printf("premaster_key_len: %u\n", ctx->premaster_key_len);
    printf("cipher_spec_set: %u\n", ctx->cipher_spec_set);
    printf("message_buffer_len: %u\n", ctx->message_buffer_len);
    printf("remote_sequence_number: %lu\n", ctx->remote_sequence_number);
    printf("local_sequence_number: %lu\n", ctx->local_sequence_number);
    printf("connection_status: %u\n", ctx->connection_status);
    printf("critical_error: %u\n", ctx->critical_error);
    printf("error_code: %u\n", ctx->error_code);
    printf("tls_buffer_len: %u\n", ctx->tls_buffer_len);
    printf("application_buffer_len: %u\n", ctx->application_buffer_len);
    printf("is_child: %u\n", ctx->is_child);
    printf("exportable: %u\n", ctx->exportable);
    printf("exportable_size: %u\n", ctx->exportable_size);
    printf("request_client_certificate: %u\n", ctx->request_client_certificate);
    printf("dtls: %u\n", ctx->dtls);
    printf("dtls_epoch_local: %u\n", ctx->dtls_epoch_local);
}
#endif /* WITH_TLS */



int
main()
{
	struct sockaddr_in sin = {.sin_family = AF_INET};
	socklen_t slen;
	int so = socket(AF_INET, SOCK_STREAM , IPPROTO_TCP);
	int epfd;
	struct epoll_event evs[1024];//fds with events happened
	
	ast(so > 0, "socket", NULL);
	
	sin.sin_port = htons(50000);
	sin.sin_addr.s_addr = INADDR_ANY;
	//inet_pton(AF_INET, "192.168.122.185", &sin.sin_addr);
	
	reuseaddr(so);
	ast(bind(so, (struct sockaddr *)&sin, sizeof(sin)) == 0, "bind", NULL);
	ast(listen(so, 5) == 0, "listen", NULL);

#ifdef WITH_TLS
        struct TLSContext *contexts[65536];//for different connections
        bzero(contexts, sizeof(*contexts));
        struct TLSContext *server_context = tls_create_context(1, TLS_V13);
        load_keys(server_context, "example.crt", "example.key");
#endif /* WITH_TLS */

	ast((epfd = epoll_create(1024)) > 0, "epoll_create", NULL);
	epoll_add(epfd, so);
	
	for (;;) {
		int n = epoll_wait(epfd, evs, 1024, 2000), i;

		ast(n >= 0, "epoll_wait", NULL);

		for (i = 0; i < n; i++) {
			ssize_t len;
			int fd = evs[i].data.fd;
			unsigned char buf[1024];
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
			char *sndbuf, *rcvbuf;
			const int peek = MSG_PEEK | MSG_DONTWAIT;
			struct tcp_repair_opt opts[4];
			const int dopt = -1;
#endif /* DO_REPAIR */

			if (evs[i].events & EPOLLERR) {
				close(fd);
				continue;
			}

			slen = sizeof(sin);
                        int newfd;
			if (fd == so) {
				newfd = accept(so, (struct sockaddr *)&sin,
						&slen);
				ast(newfd > 0, "accept", NULL);
				reuseaddr(newfd);
                                //make it non blocking
                                ioctl(newfd, FIONBIO, &(int){1}); 
				epoll_add(epfd, newfd);
				continue;
			}

            len = read(fd, buf, sizeof(buf));
			ast(len >= 0, "read", NULL);
			if (len == 0) {
				close(fd);
#ifdef WITH_TLS
            tls_destroy_context(contexts[fd]);
#endif /* WITH_TLS */
			continue;
			}
#ifdef WITH_TLS
            if (!contexts[fd]) {
                    //send SERVER HELLO
                    contexts[fd] = tls_accept(server_context);
                    tls_request_client_certificate(contexts[fd]);
                    tls_make_exportable(contexts[fd], 1);

                    handshake_reading(contexts[fd], buf, len, fd);

                    //send server hello
                    send_pending(fd, contexts[fd]);
                    continue;
            } else if (tls_established(contexts[fd]) != 1) {
                    //receive new key from client
                    handshake_reading(contexts[fd], buf, len, fd);

                    //server send finish message 
                    send_pending(fd, contexts[fd]);

                    if (!tls_established(contexts[fd]))
						continue;
#ifdef WITH_KTLS
					/* make ktls */
					if (tls_established(contexts[fd]) == 1)
					{
						//printf("tls version before tls_make_ktls: %x\n", fd_state[fd].tls_context->version);
						ast(tls_make_ktls(contexts[fd], fd) == 0, "tls_make_ktls 0", NULL);
					}
#endif /* WITH_KTLS */
            }

#ifndef WITH_KTLS
			len = tls_read(contexts[fd], buf, sizeof(buf) - 1);
//printf("tls read %d bytes after establishing tls\n", len);
#endif /* WITH_KTLS */

#endif /* WITH_TLS */ 

#ifdef DO_REPAIR
			ast(setsockopt(fd, IPPROTO_TCP, TCP_REPAIR, &(int){1},
				sizeof(int)) == 0, "setsockopt", NULL);
#ifdef WITH_TLS
    		int tls_export_context_size = 0;
    		unsigned char tls_export_buf[0xFFFF];
#ifdef WITH_KTLS
    		ast(tls_unmake_ktls(contexts[fd], fd) == 0, "tls_unmake_ktls", NULL);
#endif /* WITH_KTLS */

//printf("\nTLScontext before serialize, after unmake_ktls\n");
//print_tls_context(contexts[fd]);

    		tls_export_context_size = tls_export_context(contexts[fd], tls_export_buf, sizeof(tls_export_buf), 1);
    		ast(tls_export_context_size > 0, "tls_export_context", NULL);
#endif /* WITH_TLS */
			slen = sizeof(info);
			ast(getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &slen)	== 0, "getsockopt", NULL);
			ast(info.tcpi_state == TCP_ESTABLISHED, NULL, "not established");

			ast(ioctl(fd, SIOCOUTQ, &sndq_len) == 0, "ioctl", NULL);
			ast(ioctl(fd, SIOCOUTQNSD, &unsndq_len) == 0, "ioctl", NULL);
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
//~~~restore~~~//
			ast((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))
					> 0, "socket", NULL);
			reuseaddr(fd);

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

			ast(setsockopt(fd, IPPROTO_TCP, TCP_TIMESTAMP, &ts,
					sizeof(ts)) == 0, "setsockopt", NULL);
			ast(setsockopt(fd, IPPROTO_TCP, TCP_REPAIR_WINDOW,
					&window, sizeof(window)) == 0,
					"setsockopt", NULL);

#ifdef WITH_TLS
    		struct TLSContext *imported_context;
    		if (tls_export_context_size > 0) 
    		{
#ifdef PROFILE
			struct timespec start_time, end_time;
            clock_gettime(CLOCK_MONOTONIC, &start_time);
#endif /* PROFILE */
    		        imported_context = tls_import_context(tls_export_buf, tls_export_context_size); 
#ifdef PROFILE
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            printf("tls_import_context: %lf\n", diff_timespec(&end_time, &start_time));
#endif /* PROFILE */
    		        if (imported_context) 
    		        {
    		                tls_make_exportable(imported_context, 1);
    		        }
    		        else
    		        {
    		                perror("tls_import_context");
    		                exit(0);
    		        } 
    		} 

//printf("\nTLScontext after deserialize, before make_ktls\n");
//print_tls_context(imported_context);

#ifdef WITH_KTLS
    		ast(tls_make_ktls(imported_context, fd) == 0, "tls_make_ktls in restore", NULL);
#endif /* WITH_KTLS */

#endif /* WITH_TLS */
			ast(setsockopt(fd, IPPROTO_TCP, TCP_REPAIR, &dopt,
				sizeof(dopt)) == 0, "setsockopt", NULL);

			epoll_add(epfd, fd);
#endif /* DO_REPAIR */

#ifdef WITH_TLS
#ifdef WITH_KTLS
			len = write(fd, HTTPHDR, strlen(HTTPHDR) + 1);
			ast(len > 0, "write1", NULL);
printf("ktls write\n");
#else
            len = tls_write(contexts[fd], (const unsigned char *)HTTPHDR,
					strlen(HTTPHDR) + 1);
            //tls_close_notify(context);
            send_pending(fd, contexts[fd]);
//printf("tls write\n");
#endif /* WITH_KTLS */
#else
			len = write(fd, HTTPHDR, strlen(HTTPHDR) + 1);
			ast(len > 0, "write2", NULL);
#endif /* WITH_TLS */
		}
	}

#ifdef WITH_TLS
        tls_destroy_context(server_context);
#endif /* WITH_TLS */
	return 0;
}
