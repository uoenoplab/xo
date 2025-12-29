#define _GNU_SOURCE
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
#include <assert.h>
#include <sched.h>
#include <netinet/in.h>
#include <net/if.h>
#include <stdbool.h>

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

#ifdef DO_REPAIR
#include "forward.h"              // tc
#include "info_to_migrate.pb-c.h" // protobuf
#define HANDOFF_MSG 3             // migration
#define READY_MSG 4
#define END_MSG 5
#define MAC_ADDRSTRLEN 20

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

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_ether.h>

#endif /* DO_REPAIR */

//#ifdef PROFILE
#include <time.h>
// https://stackoverflow.com/questions/68804469/subtract-two-timespec-objects-find-difference-in-time-or-duration
double diff_timespec(const struct timespec *time1, const struct timespec *time0)
{
        return (time1->tv_sec - time0->tv_sec) + (time1->tv_nsec - time0->tv_nsec) / 1000000000.0;
}
#define D(_fmt, ...)                                                \
        do                                                          \
        {                                                           \
                struct timeval _t0;                                 \
                gettimeofday(&_t0, NULL);                           \
                fprintf(stderr, "%03d.%06d %s [%d] " _fmt "",       \
                        (int)(_t0.tv_sec % 1000), (int)_t0.tv_usec, \
                        __FUNCTION__, __LINE__, ##__VA_ARGS__);     \
        } while (0)

struct timespec start_time, end_time;
//#endif /* PROFILE */

#define NUM_FAKE 4
//#define CONTENT_SIZE 1024
int CONTENT_SIZE;
//int CONTENT_SIZE = 8*1024;
#define HTTPHDR_LEN 81
static char *HTTPHDR = (char *)"HTTP/1.1 200 OK\r\n"
                               "Connection: keep-alive\r\n"
                               "Server: Apache/2.2.800\r\n"
                               "Content-Length: ";
#define NUM_THREADS 8
#ifdef DO_FREQUENCY
// 0: migration once 1: every request n: every n requests
//#define MIGRATION_FREQUENCY 1
int MIGRATION_FREQUENCY;
#endif /* DO_FREQUENCY */
#define Q_SIZE 1000

/* global variables */
int control_original_fds[NUM_THREADS][NUM_FAKE] = {0}; // control socket fds
int control_fake_fds[NUM_THREADS] = {0};
int designated_thread = 0;         // ensure control connection is handled by the designated thread
int http_write_offset[1024] = {0}; // global partially write offset table
char *httpbuf;
ssize_t httplen, httphdrlen;
pthread_once_t once_control = PTHREAD_ONCE_INIT;
char fake_my_ip[INET_ADDRSTRLEN]; // fake server's IP
int fake_my_ip_fd;
int fake_my_id = -1;
//bool rule_is_given_up[65535] = {0}; // recording whether the rule is given up due to full queue

#define MAX_FD 65533 // TCP_CLOSE
typedef struct
{ // network order5
        uint16_t src_port;
        uint16_t dst_port;
        uint32_t src_ip;
        uint32_t dst_ip;
} connection_tuple;

typedef struct
{
        connection_tuple tuple;
#ifdef DO_REPAIR
        bool is_ctrl;       // 1: control connection 0: data connection
        int ctrl_fake_id;   // for original and control fd, to which fake server it is connected to
        int target_fake_id; // for data fd, to which fake server it is going to migrate to
        int handoff_count;  // for frequency control
#endif /* DO_REPAIR */
#ifdef WITH_TLS
        struct TLSContext *tls_context;
        bool ktls_enabled;
#endif /* WITH_TLS */
} connection_table;

/* used for storing connection info
 * which will be used for dealing with
 * TCP_CLOSE fd (removing rules) */
connection_table fd_state[MAX_FD]; // global variable is automatically initialized to zero

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

#ifdef DO_REPAIR
// mutex for length prefix read from ctrl socket is not needed after using one ctrl socket per thread
// pthread_mutex_t control_read_mutex = PTHREAD_MUTEX_INITIALIZER;
bool hw_offload;
bool blocking_disabled = false;

// machine info
char client_ip[INET_ADDRSTRLEN], client_mac[MAC_ADDRSTRLEN];
char original_ip[INET_ADDRSTRLEN], original_mac[MAC_ADDRSTRLEN];
char fake_ip[NUM_FAKE][INET_ADDRSTRLEN], fake_mac[NUM_FAKE][MAC_ADDRSTRLEN];

struct tcp_info_sub
{
        uint8_t tcpi_state;
        uint8_t tcpi_ca_state;
        uint8_t tcpi_retransmits;
        uint8_t tcpi_probes;
        uint8_t tcpi_backoff;
        uint8_t tcpi_options;
        uint8_t tcpi_snd_wscale : 4;
        uint8_t tcpi_rcv_wscale : 4;
};

#ifdef DO_NBTC

typedef struct
{
        bool skip;
//        operation_t op;
        const char *src_ip;
        const char *dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        const char *new_src_ip;
        const char *new_src_mac;
        const char *new_dst_ip;
        const char *new_dst_mac;
        uint16_t new_src_port;
        uint16_t new_dst_port;
        bool block;
        bool hw_offload;
} rule_args;

typedef struct
{
        int size;
        int count;
        int head;
        int tail;
        rule_args *buffer;
        pthread_mutex_t lock;
        pthread_cond_t not_empty;
        pthread_cond_t not_full;
}rule_queue_t;
rule_queue_t *q;

void rule_queue_init(rule_queue_t *q, int q_size)
{
        q->size= q_size;
        q->count = 0;
        q->head = 0;
        q->tail = 0;
        q->buffer = (rule_args *)malloc(q->size * sizeof(rule_args));
        pthread_mutex_init(&q->lock, NULL);
        pthread_cond_init(&q->not_empty, NULL);
        pthread_cond_init(&q->not_full, NULL);
}

void rule_queue_destroy(rule_queue_t *q)
{
        free(q->buffer);
        pthread_mutex_destroy(&q->lock);
        pthread_cond_destroy(&q->not_empty);
        pthread_cond_destroy(&q->not_full);
}

bool rule_enqueue(rule_queue_t *q, rule_args *arg)
{
//clock_gettime(CLOCK_MONOTONIC, &start_time);
        pthread_mutex_lock(&q->lock);
        if (q->count == q->size)
        {
                apply_redirection_dummy_str(arg->src_ip, arg->dst_ip,
                                        arg->src_port, arg->dst_port,
                                        arg->new_src_ip, arg->new_src_mac,
                                        arg->new_dst_ip, arg->new_dst_mac,
                                        arg->new_src_port, arg->new_dst_port);
                pthread_mutex_unlock(&q->lock);
                return false;
        }
        else
        {
                q->buffer[q->tail] = *arg;
                q->tail = (q->tail + 1) % q->size;
                q->count++;
                pthread_cond_signal(&q->not_empty);
                pthread_mutex_unlock(&q->lock);
                return true;
        }
}

bool rule_in_queue(rule_queue_t *q, int client_port)
{
        pthread_mutex_lock(&q->lock);
        for (int i = 0; i < q->count; i++)
        {
                int rule_pos = (q->head + i) % q->size;
                if (q->buffer[rule_pos].src_port == client_port)
                {
			if (q->buffer[rule_pos].skip)
			{// keep searching if the matched rule has already been cancelled
				continue;
			}
			else
			{
                        	q->buffer[rule_pos].skip = true;
                        	pthread_mutex_unlock(&q->lock);
                        	return true;
			}
                }
        }
        pthread_mutex_unlock(&q->lock);
        return false;
}

void *rule_q_consumer(void *queue)
{
        rule_queue_t *q = (rule_queue_t *)queue;
        for (;;)
        {
                rule_args arg;
                pthread_mutex_lock(&q->lock);
                while (q->count == 0)
                {
                        pthread_cond_wait(&q->not_empty, &q->lock);
                }

                arg = q->buffer[q->head];
                q->head = (q->head + 1) % q->size;
                q->count--;
                pthread_cond_signal(&q->not_full);
                pthread_mutex_unlock(&q->lock);

                if (arg.skip)
                {
                        continue;
                }
                else
                {
                        ast(apply_redirection_str(
                                arg.src_ip, arg.dst_ip,
                                arg.src_port, arg.dst_port,
                                arg.new_src_ip, arg.new_src_mac,
                                arg.new_dst_ip, arg.new_dst_mac,
                                arg.new_src_port, arg.new_dst_port,
                                arg.block, arg.hw_offload) == 0, "apply_redirection_str", NULL);
                }
        }

        return NULL;
}
#endif /* DO_NBTC */

/* ebpf is always needed for blocking */
int ingress_map = -1;
int egress_map = -1;
struct flow_key
{
        __u32 src_ip;
        __u32 dst_ip;
        __u16 src_port;
        __u16 dst_port;
};
struct map_value
{
        __u8 block;
        __u8 redirect;
        __u8 modify_src_ip;
        __u32 new_src_ip;
        __u32 new_dst_ip;
        unsigned char new_src_mac[ETH_ALEN];
        unsigned char new_dst_mac[ETH_ALEN];
};

#endif /* DO_REPAIR */

typedef struct
{
        int data_socket;
        int worker_id;
} socket_info;

ssize_t generate_httphdr(size_t content_length, char *buf)
{
        char *c = buf;
        c = mempcpy(c, HTTPHDR, HTTPHDR_LEN);
        c += sprintf(c, "%lu\r\n\r", content_length);
        *c++ = '\n';
        return c - buf;
}



static void epoll_add(int epfd, int fd)
{
        struct epoll_event ev; // used for epoo_ctl()
        bzero(&ev, sizeof(ev));
        ev.data.fd = fd;
        ev.events = EPOLLIN | EPOLLERR;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == -1)
        {
                if (errno == EEXIST)
                        return;
                else
                {
                        perror("epoll_ctl in epoll_add()");
                        exit(0);
                }
        }
}

static void
reuseaddr(int fd)
{
        ast(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == 0, "setsockopt9", NULL);
        ast(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int)) == 0, "setsockopt10", NULL);
}

#ifdef WITH_TLS
static char identity_str[0xFF] = {0};
int read_from_file(const char *fname, void *buf, int max_len)
{
        FILE *f = fopen(fname, "rb");
        if (f)
        {
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

void load_keys(struct TLSContext *context, char *fname, char *priv_fname)
{
        unsigned char buf[0xFFFF];
        unsigned char buf2[0xFFFF];
        int size = read_from_file(fname, buf, 0xFFFF);
        int size2 = read_from_file(priv_fname, buf2, 0xFFFF);
        if (size > 0)
        {
                if (context)
                {
                        tls_load_certificates(context, buf, size);
                        tls_load_private_key(context, buf2, size2);
                        // tls_print_certificate(fname);
                }
        }
}

int send_pending(int clnt_sock, struct TLSContext *context)
{
        unsigned int out_buffer_len = 0;
        const unsigned char *out_buffer = tls_get_write_buffer(context, &out_buffer_len);
        unsigned int out_buffer_index = 0;
        int send_res = 0;

        while ((out_buffer) && (out_buffer_len > 0))
        {
                int res = send(clnt_sock, (char *)&out_buffer[out_buffer_index],
                               out_buffer_len, MSG_DONTWAIT);
                if (res <= 0)
                {
                        send_res = res;
                        break;
                }
                out_buffer_len -= res;
                out_buffer_index += res;
        }
        tls_buffer_clear(context);
        return send_res;
}

int verify_signature(struct TLSContext *context, struct TLSCertificate **certificate_chain, int len)
{
        if (len)
        {
                struct TLSCertificate *cert = certificate_chain[0];
                if (cert)
                {
                        snprintf(identity_str, sizeof(identity_str), "%s, %s(%s) (issued by: %s)", cert->subject, cert->entity, cert->location, cert->issuer_entity);
                        fprintf(stderr, "Verified: %s\n", identity_str);
                }
        }
        return no_error;
}

int handshake_reading(struct TLSContext *context, const void *buf, int len, int fd)
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

#ifdef DO_REPAIR
static int
restore_queue(int fd, int q, const uint8_t *buf, uint32_t len, int need_repair)
{ // used in deserialize
        int ret, max_chunk = len, off = 0;
        if (need_repair)
                ast(setsockopt(fd, IPPROTO_TCP, TCP_REPAIR_QUEUE, &q, sizeof(q)) == 0, "setsockopt11", NULL);
        do
        {
                int chunk = len > max_chunk ? max_chunk : len;
                ret = send(fd, buf + off, chunk, 0);
                if (ret <= 0)
                {
                        if (max_chunk > 1024 /* see tcp_export.cpp */)
                        {
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

int get_peer_port(int fd)
{ // used in control plane
        struct sockaddr_in addr = {.sin_family = AF_INET};
        socklen_t addr_len = sizeof(addr);
        if (getpeername(fd, (struct sockaddr *)&addr, &addr_len) != 0)
                return 0;
        else
                return addr.sin_port;
}

void parse_mac(const char *mac_str, unsigned char *mac)
{ // used in ebpf rule insertion
        int values[6];
        if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
                   &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]) == 6)
                for (int i = 0; i < 6; ++i)
                        mac[i] = (uint8_t)values[i];
        else
        {
                printf("sscanf in parse_mac error\n");
                exit(0);
        }
}
#endif /* DO_REPAIR */

#ifdef DO_REPAIR
void get_my_ip()
{
        struct sockaddr_in local_addr;
        socklen_t locl_addr_len = sizeof(local_addr);

        ast(getsockname(fake_my_ip_fd, (struct sockaddr *)&local_addr, &locl_addr_len) == 0,
            "getsockname", NULL);
        inet_ntop(AF_INET, &local_addr.sin_addr, fake_my_ip, INET_ADDRSTRLEN);

        for (int i = 0; i < NUM_FAKE; i++)
        {
                if (strcmp(fake_my_ip, fake_ip[i]) == 0)
                {
                        fake_my_id = i;
                        break;
                }
        }
        if (fake_my_id == -1)
        {
                fprintf(stderr, "Error: fake_my_ip not found in fake_ip[]\n");
                exit(0);
        }
}

ssize_t handle_ctrlfd_eagain(int epfd, int fd, char *buf, ssize_t len, char *ctrl_msg_buf, ssize_t ctrl_msg_len)
{
        ssize_t ret;
        
        for (int i = 0; i < 5; i++)
        {
                ret = write(fd, buf, len);
                if (ret == len)
                        return ret;
                else if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                        continue;
                else if (ret < 0 && (errno != EAGAIN && errno != EWOULDBLOCK))
                {
                        perror("write control fd other error");
                        exit(0);
                }
                else if (ret < len)
                {
                        perror("write control fd partially");
                        exit(0);
                }
        }
        if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
                struct epoll_event event;
                event.events = EPOLLOUT;
                event.data.fd = fd;
                ast(epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &event) == 0, "epoll_ctl in handle_ctrlfd_eagain", NULL);

                ctrl_msg_buf = buf;
                ctrl_msg_len = len;
        }

        return ret;
}
#endif /* DO_REPAIR */

void close_fd_cleanup(int fd, int epfd)
{
        ast(epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL) == 0, "epoll_ctl close_fd_cleanup", NULL);
        close(fd);
        http_write_offset[fd] = 0;
#ifdef WITH_TLS
        if (fd_state[fd].tls_context)
        {
                tls_destroy_context(fd_state[fd].tls_context);
                fd_state[fd].tls_context = NULL;
                fd_state[fd].ktls_enabled = 0;
        }
#endif /* WITH_TLS */
}

void response_ok(int fd, int epfd, char *httpbuf, ssize_t httplen)
{
#ifdef WITH_TLS
#ifdef WITH_KTLS
        ssize_t written;
        do
        {
                written = write(fd, httpbuf, httplen);
        } while (written == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
        ast(written > 0, "ktls write response OK", NULL);
#else
        ssize_t written = tls_write(fd_state[fd].tls_context, httpbuf, httplen);
        ast(written >= 0, "tls_write2", NULL);
        send_pending(fd, fd_state[fd].tls_context);
#endif /* WITH_KTLS */
#else
        ssize_t written = write(fd, httpbuf, httplen);
        ast(written > 0, "write response OK", NULL);
#endif /* WITH_TLS */
        if (written < httplen)
        {
                // partially write handling
                http_write_offset[fd] += written;
                // add it to epoll
                struct epoll_event event;
                event.events = EPOLLOUT;
                event.data.fd = fd;
                ast(epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &event) == 0, "epoll_ctl in response_ok", NULL);
        }
}

void *worker_func(void *arg)
{
#ifdef DO_FREQUENCY
        int handoff_count = 0;
#endif  /* DO_FREQUENCY */
        // printf("threadid: %lu in worker_func\n", (unsigned long)pthread_self());
        /* create epoll */
        int epfd = epoll_create(1024);
        ast(epfd > 0, "epoll_create", NULL);
        struct epoll_event events[1024];

        /* parse thread args*/
        socket_info *sock_info = (socket_info *)arg;
        int worker_id = sock_info->worker_id;

        /* process data_so */
        int data_so = sock_info->data_socket;
        epoll_add(epfd, data_so);

        free(sock_info);

#ifdef WITH_TLS
        struct TLSContext *server_context = NULL;
        server_context = tls_create_context(1, TLS_V13);
        load_keys(server_context, "example.crt", "example.key");
#endif /* WITH_TLS */

#ifdef DO_REPAIR
        /* process ctrl_so */
        int port = 60000 + worker_id; // each thread has its own control port
        struct sockaddr_in ctrl_sin;
        ctrl_sin.sin_family = AF_INET;
        ctrl_sin.sin_port = htons(port);
        ctrl_sin.sin_addr.s_addr = INADDR_ANY;

        int ctrl_so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ast(ctrl_so > 0, "ctrl_so socket()", NULL);
        reuseaddr(ctrl_so);
        ioctl(ctrl_so, FIONBIO, &(int){1});
        ast(setsockopt(ctrl_so, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) == 0, "setsockopt TCP_NODELAY2", NULL);
        ast(setsockopt(ctrl_so, IPPROTO_TCP, TCP_QUICKACK, &(int){1}, sizeof(int)) == 0, "setsockopt TCP_QUICKACK2", NULL);

        ast(bind(ctrl_so, (struct sockaddr *)&ctrl_sin, sizeof(ctrl_sin)) == 0, "ctrl_so bind()", NULL);
        ast(listen(ctrl_so, 20) == 0, "ctrl_so listen()", NULL);

        epoll_add(epfd, ctrl_so);

        /* prepare for serialize & deserialize */
        struct tcp_info_sub info; // ? this has to be global

        /* prepare for multiple backends */
        /* these are handles used for decide new target fake server */
        int data_designated_fake = 0;             // distribute data connection to different fake servers
        int ctrl_designated_fake[NUM_FAKE] = {0}; // distribute handoff control connection to different fake servers
        bool ctrl_conn_established = 0;

        /* prepare for protobuf */
        InfoToMigrate *msg_type_info;
        size_t proto_msg_len;
        uint32_t net_proto_msg_len;
        uint8_t *proto_msg_buf;
        uint8_t *combined_proto_msg_buf;

        /* prepare for write again of ctrl_fd */
        size_t ctrl_msg_len;
        uint8_t *ctrl_msg_buf;

        /* prepare for ebpf rule */
        struct flow_key key = {};
        struct map_value value = {};

#ifdef DO_TC
        if (worker_id == 0)
        {
                /* insert a fake rule to avoid first rule long delay */
                ast(apply_redirection_str(
                        "192.168.11.98",
                        "192.168.11.99",
                	8888, 9999,

                        "192.168.11.99", "3c:fd:fe:e5:ba:10",
                        "192.168.11.97", "00:15:4d:13:70:b5",
                	9999, 9998,
                        blocking_disabled, hw_offload) == 0,
                        "apply_redirection_str8989", NULL);
                printf("fake rule inserted\n");
        }
#endif /* DO_TC */
#endif /* DO_REPAIR */

        while (1)
        {
                int i;
                // printf("threadid: %lu just before epoll_wait\n", (unsigned long)pthread_self());
                int n = epoll_wait(epfd, events, 1024, 2000);
                ast(n >= 0, "epoll_wait", NULL);
                // printf("threadid: %lu just after epoll_wait %d\n", (unsigned long)pthread_self(), n);

                for (i = 0; i < n; i++)
                {
                        //printf("worker_id %d\n", worker_id);
                        int fd = events[i].data.fd;

                        if (events[i].events & EPOLLERR)
                        {
                                close_fd_cleanup(fd, epfd);
                                continue;
                        }

                        if (events[i].events & EPOLLOUT)
                        { 
#ifdef DO_REPAIR
                                if (fd_state[fd].is_ctrl)
                                {/* write control fd eagain handling */
                                        size_t ret;
                                        ret = write(fd, ctrl_msg_buf, ctrl_msg_len);
                                        if (ret == ctrl_msg_len)
                                        {
                                                free(ctrl_msg_buf);
                                                ctrl_msg_buf = NULL;

                                                struct epoll_event event;
                                                event.events = EPOLLIN | EPOLLERR;
                                                event.data.fd = fd;
                                                ast(epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &event) == 0, "epoll_ctl in partially write EPOLLERR", NULL);
                                                continue;
                                        }
                                        else
                                        {
                                                perror("write ctrl_fd again");
                                                exit(0);
                                        }
                                }
#endif /* DO_REPAIR */
                                /* partially write handling */
#ifdef WITH_TLS
#ifdef WITH_KTLS
                                ssize_t written = write(fd, httpbuf + http_write_offset[fd], httplen - http_write_offset[fd]);
#else /* normal tls */
                                ssize_t written = tls_write(fd_state[fd].tls_context, httpbuf + http_write_offset[fd], httplen - http_write_offset[fd]);
                                ast(written >= 0, "tls_write1", NULL);
                                send_pending(fd, fd_state[fd].tls_context);
#endif /* WITH_KTLS */
#else /* without tls */
                                ssize_t written = write(fd, httpbuf + http_write_offset[fd], httplen - http_write_offset[fd]);
#endif /* WITH_TLS */
                                if (written < 0)
                                {
                                        if (errno == EPIPE)
                                        {
                                                close_fd_cleanup(fd, epfd);
                                                continue;
                                        }
                                        else if (errno == EAGAIN || errno == EWOULDBLOCK)
                                        {
                                                continue;
                                        }
                                        else
                                        {
                                                perror("write again");
                                                exit(0);
                                        }
                                }

                                if (written > 0)
                                        http_write_offset[fd] += written;

                                if (http_write_offset[fd] == httplen)
                                {
                                        http_write_offset[fd] = 0;

                                        struct epoll_event event;
                                        event.events = EPOLLIN | EPOLLERR;
                                        event.data.fd = fd;

                                        ast(epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &event) == 0, "epoll_ctl in partially write EPOLLERR", NULL);

                                        continue;
                                }
                                continue;
                        }
                        if (fd == data_so)
                        {
                                struct sockaddr_in client_sin;
                                socklen_t slen = sizeof(client_sin);

                                int newfd = accept(data_so, (struct sockaddr *)&client_sin, &slen);
                                if (newfd == -1)
                                {
                                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                                        { // No connection was ready to be accepted
                                                continue;
                                        }
                                        else
                                        {
                                                perror("data accept");
                                                exit(0);
                                        }
                                }

                                reuseaddr(newfd);
                                ioctl(newfd, FIONBIO, &(int){1});
                                epoll_add(epfd, newfd);
#ifdef DO_REPAIR
                                /* initiate fd_state table */
                                if (newfd < MAX_FD)
                                { // keep fd_state in original server
                                        fd_state[newfd].tuple.src_port = client_sin.sin_port;
                                        fd_state[newfd].tuple.src_ip = client_sin.sin_addr.s_addr;
                                        // dst_port/ip are not necessary information
                                        fd_state[newfd].tuple.dst_port = htons(50000);
                                        fd_state[newfd].tuple.dst_ip = inet_addr(original_ip);
                                        fd_state[newfd].is_ctrl = 0;
                                        // distribute data connection to different fake servers
                                        fd_state[newfd].target_fake_id = data_designated_fake;
                                        data_designated_fake = (data_designated_fake + 1) % NUM_FAKE;
                                        // migration frequency
                                        fd_state[fd].handoff_count = 0;
#ifdef WITH_TLS
                                        fd_state[newfd].tls_context = NULL;
                                        fd_state[newfd].ktls_enabled = 0;
#endif /* WITH_TLS */
                                }
                                else
                                        printf("File descriptor %d out of range for fd_state[]\n", newfd);
#endif /* DO_REPAIR */
                                continue;
                        }
#ifdef DO_REPAIR
                        if (fd == ctrl_so)
                        {
                                struct sockaddr_in ctrl_client_sin;
                                socklen_t slen = sizeof(ctrl_client_sin);

                                if (worker_id != designated_thread)
                                { // not the designated thread
                                        continue;
                                }
                                else
                                { // the designated thread
                                        control_fake_fds[worker_id] = accept(ctrl_so, (struct sockaddr *)&ctrl_client_sin, &slen);
                                        designated_thread = (designated_thread + 1) % NUM_THREADS;
                                }
                                if (control_fake_fds[worker_id] == -1)
                                { // Non-blocking ctrl_so
                                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                                        { // No pending connection requests in the queue
                                                continue;
                                        }
                                        else
                                        {
                                                perror("ctrl accept");
                                                exit(0);
                                        }
                                }

                                reuseaddr(control_fake_fds[worker_id]);
                                ioctl(control_fake_fds[worker_id], FIONBIO, &(int){1});
                                ast(setsockopt(control_fake_fds[worker_id], IPPROTO_TCP, TCP_NODELAY, &(int){1},
                                               sizeof(int)) == 0,
                                    "setsockopt TCP_NODELAY1", NULL);
                                ast(setsockopt(control_fake_fds[worker_id], IPPROTO_TCP, TCP_QUICKACK, &(int){1},
                                               sizeof(int)) == 0,
                                    "setsockopt TCP_QUICKACK1", NULL);
                                fd_state[control_fake_fds[worker_id]].is_ctrl = 1;
                                epoll_add(epfd, control_fake_fds[worker_id]);

                                fake_my_ip_fd = control_fake_fds[worker_id];
                                pthread_once(&once_control, get_my_ip);

                                continue;
                        }
#endif /* DO_REPAIR */
#ifdef DO_REPAIR
                        if (!fd_state[fd].is_ctrl)
#else
                        else
#endif /* DO_REPAIR */
                        {// data message handling
                                char buf[65533];
                                ssize_t len_read = read(fd, buf, sizeof(buf));
                                if (len_read == -1)
                                {
                                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                                        {
                                                printf("read1 EAGAIN\n");
                                                continue;
                                        }
                                        else if (errno == EPIPE)
                                        {
                                                close_fd_cleanup(fd, epfd);
                                                continue;
                                        }
                                }
                                else if (len_read == 0)
                                {
                                        close_fd_cleanup(fd, epfd);
                                        continue;
                                }

#ifdef WITH_TLS
                                /* Establishing TLS connection */
                                if (!fd_state[fd].ktls_enabled)
                                {
                                        if (!fd_state[fd].tls_context)
                                        {
                                                fd_state[fd].tls_context = tls_accept(server_context);
                                                tls_request_client_certificate(fd_state[fd].tls_context);
                                                tls_make_exportable(fd_state[fd].tls_context, 1);
                                                /* receive client hello */
                                                handshake_reading(fd_state[fd].tls_context, buf, len_read, fd);
                                                /* send server hello */
                                                send_pending(fd, fd_state[fd].tls_context);
                                                continue;
                                        }
                                        else if (tls_established(fd_state[fd].tls_context) != 1)
                                        {
                                                // printf("tls_established != 1\n");
                                                /* receive new key from client */
                                                handshake_reading(fd_state[fd].tls_context, buf, len_read, fd);
                                                /* server send finish message */
                                                send_pending(fd, fd_state[fd].tls_context);
                                                if (!tls_established(fd_state[fd].tls_context))
                                                        continue;
#ifdef WITH_KTLS
                                                /* make ktls */
                                                if (tls_established(fd_state[fd].tls_context) == 1)
                                                {
                                                        ast(tls_make_ktls(fd_state[fd].tls_context, fd) == 0, "tls_make_ktls in tls establishment", NULL);
                                                        fd_state[fd].ktls_enabled = 1;
                                                }
#endif /* WITH_KTLS */
                                        }
                                }
#ifndef WITH_KTLS
                                len_read = tls_read(fd_state[fd].tls_context, buf, sizeof(buf) - 1);
#endif /* WITH_KTLS */
#endif /* WITH_TLS */
#ifdef DO_REPAIR
                                /* establish control connection */
                                if (ctrl_conn_established == 0 && control_fake_fds[worker_id] == 0)
                                {
                                        /***********************************************************
                                         * Only do this on original and only when receiving 1st GET.
                                         *
                                         * Before this point, GET arrived at original,
                                         * ---------------------------------------------------------
                                         * original | ctrl_conn_est == 0 | control_fake_fds == 0
                                         *   fake   | ctrl_conn_est == 0 | control_fake_fds == 0
                                         * ---------------------------------------------------------
                                         *
                                         * At this point,
                                         * original receiving 1st GET, triggered this operation
                                         *
                                         * After this point,
                                         * ---------------------------------------------------------
                                         * original | ctrl_conn_est == 1 | control_fake_fds == 0
                                         *   fake   | ctrl_conn_est == 0 | control_fake_fds == 1
                                         * ---------------------------------------------------------
                                         * which means this operation will not be triggered anymore
                                         ***********************************************************/
                                        for (int j = 0; j < NUM_FAKE; j++)
                                        {
                                                /*********************************************************
                                                 * for each thread on original server (current worker_id),
                                                 * create different dedicated ctrl connections
                                                 * between this original thread and the thread
                                                 * on different fake server with same worker_id
                                                 *********************************************************/
                                                control_original_fds[worker_id][j] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                                                ast(control_original_fds[worker_id][j] > 0, "control_original_fds[worker_id]", NULL);

                                                ast(setsockopt(control_original_fds[worker_id][j], IPPROTO_TCP, TCP_NODELAY, &(int){1},
                                                               sizeof(int)) == 0,
                                                    "setsockopt TCP_NODELAY2", NULL);
                                                ast(setsockopt(control_original_fds[worker_id][j], IPPROTO_TCP, TCP_QUICKACK, &(int){1},
                                                               sizeof(int)) == 0,
                                                    "setsockopt TCP_QUICKACK2", NULL);

                                                struct sockaddr_in new_ctrl_sin;
                                                new_ctrl_sin.sin_family = AF_INET;
                                                new_ctrl_sin.sin_port = htons(60000 + worker_id);
                                                new_ctrl_sin.sin_addr.s_addr = inet_addr(fake_ip[j]); // different fake server

                                                fd_state[control_original_fds[worker_id][j]].is_ctrl = 1;
                                                /* *************************************************************************
                                                 * this fd is used to connect to fake server j
                                                 * fd_state[control_original_fds[worker_id][j]].connect_fake_id = j;
                                                 * this ctrl conn initial target fake server is itself fake server j
                                                 * original will update ctrl_conn's target_fake_id when
                                                 * original receiving handoff back message from this control fd
                                                 * by ctrl_designated_fake[j] = (ctrl_designated_fake[j] + 1) % NUM_FAKE;
                                                 * ctrl_designated_fake[j] means handler for ctrl_fd linked to fake server j
                                                 * *************************************************************************/
                                                fd_state[control_original_fds[worker_id][j]].target_fake_id = j;

                                                /* one thread, one epoll */
                                                epoll_add(epfd, control_original_fds[worker_id][j]);

                                                ast(connect(control_original_fds[worker_id][j], (struct sockaddr *)&new_ctrl_sin,
                                                            sizeof(new_ctrl_sin)) == 0, "connect ctrl_fd", NULL);
                                                ioctl(control_original_fds[worker_id][j], FIONBIO, &(int){1});
                                        }
                                        ctrl_conn_established = 1;
                                }
startover:
                                /* get client port: prepare for checking TCP_CLOSE & inserting rules */
                                int peer_port = get_peer_port(fd);

                                /* Handling TCP_CLOSE fd */
                                if (peer_port == 0)
                                { // current connection has been closed by the peer
                                        if (control_fake_fds[worker_id] != 0)
                                        {
                                                // send END_MSG asking original remove redirection
                                                msg_type_info = (InfoToMigrate *)malloc(sizeof(InfoToMigrate));
                                                info_to_migrate__init(msg_type_info);

                                                msg_type_info->msg_type = END_MSG;
                                                // sending closed fd to original
                                                msg_type_info->self_addr = fd; // fd is used for looking up fd_state table
                                                msg_type_info->peer_addr = 0;  // to find the connection tuple of the closed fd
                                                msg_type_info->self_port = 0;
                                                msg_type_info->peer_port = 0;

                                                proto_msg_len = info_to_migrate__get_packed_size(msg_type_info);
                                                proto_msg_buf = malloc(proto_msg_len);

                                                info_to_migrate__pack(msg_type_info, proto_msg_buf);

                                                // dealing with boundaries: adding length prefix
                                                net_proto_msg_len = htonl(proto_msg_len);
                                                combined_proto_msg_buf = malloc(sizeof(net_proto_msg_len) + proto_msg_len);
                                                memcpy(combined_proto_msg_buf, &net_proto_msg_len, sizeof(net_proto_msg_len));
                                                memcpy(combined_proto_msg_buf + sizeof(net_proto_msg_len), proto_msg_buf, proto_msg_len);

                                                ssize_t len = write(control_fake_fds[worker_id], combined_proto_msg_buf, sizeof(net_proto_msg_len) + proto_msg_len);
                                                ast(len > 0, "write1", NULL);

                                                free(msg_type_info);
                                                free(proto_msg_buf);
                                                free(combined_proto_msg_buf);
                                        }
                                        else
                                        {
                                                printf("TCP_CLOSE fd received by original server, which is not handled by the app\n");
                                        }

                                        close_fd_cleanup(fd, epfd);
                                        continue;
                                }
                                // reserialize:
                                /* blocking */
                                key.src_ip = inet_addr(client_ip);    // ebpf needs network byte order
                                if (control_fake_fds[worker_id] == 0) // GET arrived at original
                                        key.dst_ip = inet_addr(original_ip);
                                if (control_fake_fds[worker_id] != 0) // GET arrived at fake
                                        key.dst_ip = inet_addr(fake_my_ip);
#ifdef DO_FREQUENCY
                                /* migration frequency control */
                                if (control_fake_fds[worker_id] != 0)
                                { // GET arrived at fake
                                        fd_state[fd].handoff_count++;
                                        if (fd_state[fd].handoff_count > MIGRATION_FREQUENCY)
                                        {
                                                /**************************************************************
                                                 * When only do migration once, i.e. MIGRATION_FREQUENCY is 0,
                                                 * it should respond here as long as it is on fake server,which
                                                 * means it just done once migration(from client to fake).
                                                 **************************************************************/
                                                response_ok(fd, epfd, httpbuf, httplen);
                                                fd_state[fd].handoff_count = 0;
                                                continue;
                                        }
                                        else if (fd_state[fd].handoff_count == MIGRATION_FREQUENCY)
                                        {
                                                /**************************************************************
                                                 * When migrate every n requests, and hits n,
                                                 * fake server should handoff to original server here,
                                                 * and clean up the counter.
                                                 * ------------------------------------------------------------
                                                 * When migrate every request, i.e. MIGRATION_FREQUENCY is 1,
                                                 * fake server should handoff to original server here,
                                                 * and clean up the counter.
                                                 **************************************************************/
                                                fd_state[fd].handoff_count = 0;
                                        }
                                        else if (fd_state[fd].handoff_count < MIGRATION_FREQUENCY)
                                        {
                                                /**************************************************************
                                                 * When migrate every n requests, i.e. MIGRATION_FREQUENCY is n
                                                 * and the current migration count is less than n,
                                                 * fake server should responde here,
                                                 * and keep couter increasing until it hits n.
                                                 **************************************************************/
                                                response_ok(fd, epfd, httpbuf, httplen);
                                                continue;
                                        }
                                }
#endif /* DO_FREQUENCY */
                                key.src_port = peer_port;
                                key.dst_port = htons(50000);

                                value.block = 1;
                                value.redirect = 0;
#ifdef PROFILE
                                clock_gettime(CLOCK_MONOTONIC, &start_time);
#endif /* PROFILE */
                                ast(bpf_map_update_elem(ingress_map, &key, &value, BPF_ANY) == 0,
                                    "error bpf_map_update_elem blocking c->o", NULL);
#ifdef PROFILE
                                clock_gettime(CLOCK_MONOTONIC, &end_time);
                                if (control_fake_fds[worker_id] == 0)
                                        printf("blocking client -> original: %.9lf\n", diff_timespec(&end_time, &start_time));
                                if (control_fake_fds[worker_id] != 0)
                                        printf("blocking client -> fake: %.9lf\n", diff_timespec(&end_time, &start_time));
#endif /* PROFILE */
                                /* serialize */
#ifdef PROFILE
                                struct timespec start_time1, end_time1;
                                clock_gettime(CLOCK_MONOTONIC, &start_time1);
#endif /* PROFILE */
                                ast(setsockopt(fd, IPPROTO_TCP, TCP_REPAIR, &(int){1}, sizeof(int)) == 0,
                                    "setsockopt serialize", NULL);
#ifdef WITH_TLS
#ifdef PROFILE
                                clock_gettime(CLOCK_MONOTONIC, &start_time);
#endif /* PROFILE */
#ifdef WITH_KTLS
                                /* serialize ktls context without using tlse */
                                int ktlsbuf_len = 0;
                                uint8_t *ktlsbuf_data = NULL;

                                ktlsbuf_len = 2 * sizeof(struct tls12_crypto_info_aes_gcm_256);
                                ktlsbuf_data = malloc(ktlsbuf_len);

                                struct tls12_crypto_info_aes_gcm_256 *crypto_info_send = ktlsbuf_data;
                                struct tls12_crypto_info_aes_gcm_256 *crypto_info_recv = ktlsbuf_data +
                                                                                         sizeof(struct tls12_crypto_info_aes_gcm_256);

                                socklen_t optlen = sizeof(struct tls12_crypto_info_aes_gcm_256);
                                if (getsockopt(fd, SOL_TLS, TLS_TX, crypto_info_send, &optlen))
                                {
                                        fprintf(stderr, "Couldn't get TLS_TX option (%s)\n", strerror(errno));
                                        exit(EXIT_FAILURE);
                                }

                                optlen = sizeof(struct tls12_crypto_info_aes_gcm_256);
                                if (getsockopt(fd, SOL_TLS, TLS_RX, crypto_info_recv, &optlen))
                                {
                                        fprintf(stderr, "Couldn't get TLS_RX option (%s)\n", strerror(errno));
                                        exit(EXIT_FAILURE);
                                }
#else  /* TLS */
                                int tls_export_context_size = 0;
                                unsigned char tls_export_buf[0xFFFF];
                                tls_export_context_size = tls_export_context(fd_state[fd].tls_context, tls_export_buf, sizeof(tls_export_buf), 1);
                                ast(tls_export_context_size > 0, "tls_export_context serialize", NULL);
#endif /* WITH_KTLS */
#ifdef PROFILE
                                clock_gettime(CLOCK_MONOTONIC, &end_time);
                                printf("serialize tls: %.9lf\n", diff_timespec(&end_time, &start_time));
#endif /* PROFILE */
#endif /* WITH_TLS */
                                socklen_t slen = sizeof(info);
                                ast(getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &slen) == 0,
                                    "getsockopt", NULL);
                                ast(info.tcpi_state == TCP_ESTABLISHED || info.tcpi_state == TCP_CLOSE_WAIT,
                                    "getsockopt TCP_INFO, not established", NULL);

                                int sendq_len, unsentq_len, recvq_len;
                                ast(ioctl(fd, SIOCOUTQ, &sendq_len) == 0, "ioctl", NULL);
                                ast(ioctl(fd, SIOCOUTQNSD, &unsentq_len) == 0, "ioctl", NULL);
                                ast(ioctl(fd, SIOCINQ, &recvq_len) == 0, "ioctl", NULL);

                                uint32_t mss, ts;
                                socklen_t olen_mss = sizeof(mss);
                                socklen_t olen_ts = sizeof(ts);
                                ast(getsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &mss, &olen_mss) == 0,
                                    "getsockopt", NULL);
                                ast(getsockopt(fd, IPPROTO_TCP, TCP_TIMESTAMP, &ts, &olen_ts) == 0,
                                    "getsockopt", NULL);

                                struct tcp_repair_window window;
                                slen = sizeof(window);
                                ast(getsockopt(fd, IPPROTO_TCP, TCP_REPAIR_WINDOW, &window, &slen) == 0,
                                    "getsockopt", "REPAIR_WINDOW");

                                struct sockaddr_in sin;
                                bzero(&sin, sizeof(sin));
                                sin.sin_family = AF_INET;
                                slen = sizeof(sin);
                                ast(getsockname(fd, (struct sockaddr *)&sin, &slen) == 0, "getsockname", NULL);

                                struct sockaddr_in sin2;
                                bzero(&sin2, sizeof(sin2));
                                sin2.sin_family = AF_INET;
                                slen = sizeof(sin2);
                                ast(getpeername(fd, (struct sockaddr *)&sin2, &slen) == 0,
                                    "getpeername serializing", NULL);

                                const int qid_snd = TCP_SEND_QUEUE;
                                // this tells the kernel the subsequent operation is targeting the send queue of the socket
                                ast(setsockopt(fd, IPPROTO_TCP, TCP_REPAIR_QUEUE, &qid_snd, sizeof(qid_snd)) == 0, "setsockopt TCP_REPAIR_QUEUE send", NULL);
                                socklen_t seqno_send;
                                slen = sizeof(seqno_send);
                                ast(getsockopt(fd, IPPROTO_TCP, TCP_QUEUE_SEQ, &seqno_send, &slen) == 0,
                                    "getsockopt", NULL);
                                uint8_t *sndbuf;
                                if (sendq_len)
                                {
                                        ast((sndbuf = calloc(1, sendq_len + 1)) != NULL, "calloc", NULL);
                                        ast(recv(fd, sndbuf, sendq_len + 1, MSG_PEEK | MSG_DONTWAIT) == sendq_len, "recv1 sendq_len", NULL);
                                }

                                const int qid_rcv = TCP_RECV_QUEUE;
                                ast(setsockopt(fd, IPPROTO_TCP, TCP_REPAIR_QUEUE, &qid_rcv, sizeof(qid_rcv)) == 0, "setsockopt TCP_REPAIR_QUEUE receive", NULL);
                                socklen_t seqno_recv;
                                slen = sizeof(seqno_recv);
                                ast(getsockopt(fd, IPPROTO_TCP, TCP_QUEUE_SEQ, &seqno_recv, &slen) == 0,
                                    "getsockopt", NULL);
                                uint8_t *rcvbuf;
                                if (recvq_len)
                                {
                                        ast((rcvbuf = calloc(1, recvq_len + 1)) != NULL, "calloc", NULL);
                                        ast(recv(fd, rcvbuf, recvq_len + 1, MSG_PEEK | MSG_DONTWAIT) == recvq_len, "recv2 recvq_len", NULL);
                                }
#ifdef PROFILE
                                clock_gettime(CLOCK_MONOTONIC, &end_time1);
                                printf("serialize tcp + tls: %.9lf\n", diff_timespec(&end_time1, &start_time1));
#endif /* PROFILE */

                                /* clean up */
                                close_fd_cleanup(fd, epfd);

                                /* pack & send handoff msg */
                                InfoToMigrate *migration_info = (InfoToMigrate *)malloc(sizeof(InfoToMigrate));
                                info_to_migrate__init(migration_info);

                                migration_info->msg_type = HANDOFF_MSG;
#ifdef WITH_TLS
                                // tls variables setting up
                                /* packing ktls context extracted by getsockopt */
#ifdef WITH_KTLS
                                migration_info->buf.len = ktlsbuf_len;
                                migration_info->buf.data = ktlsbuf_data;
#else  /* TLS */
                                migration_info->buf.len = tls_export_context_size;
                                migration_info->buf.data = tls_export_buf;
#endif /* WITH_KTLS */
#endif /* WITH_TLS */
                                // tcp variables setting up
                                migration_info->sendq_len = sendq_len;
                                migration_info->unsentq_len = unsentq_len;
                                migration_info->recvq_len = recvq_len;
                                migration_info->mss = mss;
                                migration_info->timestamp = ts;
                                migration_info->send_wscale = info.tcpi_snd_wscale;
                                migration_info->recv_wscale = info.tcpi_rcv_wscale;
                                migration_info->snd_wl1 = window.snd_wl1;
                                migration_info->snd_wnd = window.snd_wnd;
                                migration_info->max_window = window.max_window;
                                migration_info->rev_wnd = window.rcv_wnd;
                                migration_info->rev_wup = window.rcv_wup;
                                migration_info->self_addr = sin.sin_addr.s_addr;
                                migration_info->self_port = sin.sin_port;
                                migration_info->peer_addr = sin2.sin_addr.s_addr;
                                migration_info->peer_port = sin2.sin_port;
                                migration_info->seq = seqno_send;
                                migration_info->ack = seqno_recv;
                                migration_info->sendq.len = sendq_len;
                                migration_info->sendq.data = sndbuf;
                                migration_info->recvq.len = recvq_len;
                                migration_info->recvq.data = rcvbuf;

                                size_t proto_len = info_to_migrate__get_packed_size(migration_info);
                                uint8_t *proto_buf = malloc(proto_len);
                                info_to_migrate__pack(migration_info, proto_buf);
                                // dealing with boundaries: adding length prefix
                                uint32_t net_proto_len = htonl(proto_len);
                                uint8_t *combined_buf = malloc(sizeof(net_proto_len) + proto_len);
                                memcpy(combined_buf, &net_proto_len, sizeof(net_proto_len));
                                memcpy(combined_buf + sizeof(net_proto_len), proto_buf, proto_len);
                                // sending length and message, determine dst fd
                                int ctrl_fd;
                                if (control_fake_fds[worker_id] != 0) // on fake server
                                        ctrl_fd = control_fake_fds[worker_id];
                                else // on original server
                                        ctrl_fd = control_original_fds[worker_id][fd_state[fd].target_fake_id];
                                ssize_t len = write(ctrl_fd, combined_buf, proto_len + sizeof(net_proto_len));
                                if (len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                                        len = handle_ctrlfd_eagain(epfd, ctrl_fd, combined_buf, proto_len + sizeof(net_proto_len), ctrl_msg_buf, ctrl_msg_len);

                                /* clean up */
                                free(proto_buf);
                                proto_buf = NULL;
                                free(migration_info);
                                migration_info = NULL;
                                if (len >= 0)
                                {
                                        free(combined_buf);
                                        combined_buf = NULL;
                                }
                                if (sendq_len) 
                                {
                                        free(sndbuf);
                                        sndbuf = NULL;
                                }
                                if (sendq_len) 
                                {
                                        free(rcvbuf);
                                        rcvbuf = NULL;
                                }
#ifdef WITH_KTLS
                                /* release ktls context buf */
                                if (ktlsbuf_data != NULL)
                                        free(ktlsbuf_data);
#endif /* WITH_KTLS */
                                continue;
                        } // end if(data)

                        if (fd_state[fd].is_ctrl)
                        { // control msg handling
                                /* read control msg */
                                uint32_t net_msg_len, msg_len;
                                ssize_t len = read(fd, &net_msg_len, sizeof(net_msg_len)); // read length prefix
                                if (len == -1)
                                {
                                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                                                continue;
                                        else
                                        {
                                                perror("read length prefix");
                                                exit(0);
                                        }
                                }
                                if (len == 0)
                                {
                                        //printf("control message read() len == 0\n");
                                        close_fd_cleanup(fd, epfd);
                                        continue;
                                }
                                ast(len == sizeof(net_msg_len), "read2", NULL);
                                ast(setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &(int){1}, sizeof(int)) == 0,
                                    "setsockopt TCP_QUICKACK3", NULL);

                                msg_len = ntohl(net_msg_len);
                                if (msg_len == 0)
                                {
                                        printf("control meassage msg_len == 0\n");
                                        close_fd_cleanup(fd, epfd);
                                        continue;
                                }

                                uint8_t *msg_buf = malloc(msg_len);
                                ast(msg_buf > 0, "malloc(msg_len)", NULL);

                                len = read(fd, msg_buf, msg_len); // read real message
                                // ast(len == msg_len, "msg read", NULL);

                                if (len < msg_len)
                                { // deal with non-complete message
                                        continue;
                                }

                                /* unpack protobuf msg */
                                InfoToMigrate *new_migration_info =
                                    info_to_migrate__unpack(NULL, msg_len, msg_buf);
                                ast(new_migration_info != NULL, "unpack protobuf msg", NULL);

                                free(msg_buf);

                                if (new_migration_info->msg_type == HANDOFF_MSG)
                                {
#ifdef PROFILE
                                        struct timespec start_time2, end_time2;
                                        clock_gettime(CLOCK_MONOTONIC, &start_time2);
#endif /* PROFILE */
                                        int rfd;
                                        struct sockaddr_in new_sin, new_sin2;
                                        struct tcp_repair_window new_window;
#ifdef WITH_TLS
                                        struct TLSContext *imported_context;
#endif /* WITH_TLS */
                                        /* restore tcp connection */
                                        ast((rfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) > 0,
                                            "socket1", NULL);

                                        /* setting up fd status */
                                        fd_state[rfd].is_ctrl = 0;
                                        fd_state[rfd].handoff_count = 0;

                                        reuseaddr(rfd);
                                        ioctl(rfd, FIONBIO, &(int){1});
                                        ast(setsockopt(rfd, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) == 0, "setsockopt TCP_NODELAY3", NULL);
                                        ast(setsockopt(rfd, IPPROTO_TCP, TCP_QUICKACK, &(int){1}, sizeof(int)) == 0, "setsockopt TCP_QUICKACK4", NULL);

                                        ast(setsockopt(rfd, IPPROTO_TCP, TCP_REPAIR, &(int){1}, sizeof(int)) == 0, "setsockopt restore", NULL);
                                        const int qid_snd = TCP_SEND_QUEUE;
                                        ast(setsockopt(rfd, IPPROTO_TCP, TCP_REPAIR_QUEUE, &qid_snd,
                                                       sizeof(qid_snd)) == 0,
                                            "setsockopt1", NULL);
                                        ast(setsockopt(rfd, IPPROTO_TCP, TCP_QUEUE_SEQ, &new_migration_info->seq, sizeof(new_migration_info->seq)) == 0, "setsockopt2", NULL);
                                        const int qid_rcv = TCP_RECV_QUEUE;
                                        ast(setsockopt(rfd, IPPROTO_TCP, TCP_REPAIR_QUEUE, &qid_rcv, sizeof(qid_rcv)) == 0, "setsockopt", NULL);
                                        ast(setsockopt(rfd, IPPROTO_TCP, TCP_QUEUE_SEQ, &new_migration_info->ack, sizeof(new_migration_info->ack)) == 0, "setsockopt3", NULL);

                                        new_sin.sin_family = AF_INET;
                                        new_sin.sin_port = new_migration_info->self_port;
                                        if (fd == control_fake_fds[worker_id]) // fake receiving handoff msg
                                                new_sin.sin_addr.s_addr = inet_addr(fake_my_ip);
                                        if (control_fake_fds[worker_id] == 0) // original receiving handoff msg
                                                new_sin.sin_addr.s_addr = inet_addr(original_ip);
                                        new_sin2.sin_family = AF_INET;
                                        new_sin2.sin_port = new_migration_info->peer_port;
                                        new_sin2.sin_addr.s_addr = new_migration_info->peer_addr;

                                        ast(bind(rfd, (struct sockaddr *)&new_sin, sizeof(new_sin)) == 0, "bind after repair", NULL);
                                        ast(connect(rfd, (struct sockaddr *)&new_sin2, sizeof(new_sin2)) == 0, "connect restoration", NULL);

                                        socklen_t new_ulen = new_migration_info->unsentq_len;
                                        socklen_t new_len = new_migration_info->sendq.len - new_ulen;

                                        if (new_len)
                                                ast(restore_queue(rfd, TCP_SEND_QUEUE, (const uint8_t *)new_migration_info->sendq.data, new_len, 1) == 0, NULL, "restore_queue");
                                        if (new_ulen)
                                        {
                                                ast(setsockopt(rfd, IPPROTO_TCP, TCP_REPAIR, &(int){-1}, sizeof(-1)) == 0, "setsockopt4", NULL);
                                                ast(restore_queue(rfd, TCP_SEND_QUEUE, (const uint8_t *)new_migration_info->sendq.data + new_len, new_ulen, 0) == 0, NULL, "restore_queue");
                                                ast(setsockopt(rfd, IPPROTO_TCP, TCP_REPAIR, &(int){1}, sizeof(int)) == 0, "setsockopt5", NULL);
                                        }
                                        if (new_migration_info->recvq.len > 0)
                                                ast(restore_queue(rfd, TCP_RECV_QUEUE, (const uint8_t *)new_migration_info->recvq.data, new_migration_info->recvq.len, 1) == 0, NULL, "restore_queue");

                                        struct tcp_repair_opt opts[4];
                                        bzero(opts, sizeof(opts));
                                        opts[0].opt_code = TCPOPT_SACK_PERM;
                                        opts[0].opt_val = 0;
                                        opts[1].opt_code = TCPOPT_WINDOW;
                                        opts[1].opt_val = new_migration_info->send_wscale +
                                                          (new_migration_info->recv_wscale << 16);
                                        opts[2].opt_code = TCPOPT_TIMESTAMP;
                                        opts[2].opt_val = 0;
                                        opts[3].opt_code = TCPOPT_MSS;
                                        opts[3].opt_val = new_migration_info->mss;

                                        ast(setsockopt(rfd, IPPROTO_TCP, TCP_REPAIR_OPTIONS, opts, sizeof(struct tcp_repair_opt) * 4) == 0, "setsockopt opts", NULL);
                                        ast(setsockopt(rfd, IPPROTO_TCP, TCP_TIMESTAMP, &new_migration_info->timestamp, sizeof(new_migration_info->timestamp)) == 0, "setsockopt6", NULL);

                                        new_window.snd_wl1 = new_migration_info->snd_wl1;
                                        new_window.snd_wnd = new_migration_info->snd_wnd;
                                        new_window.max_window = new_migration_info->max_window;
                                        new_window.rcv_wnd = new_migration_info->rev_wnd;
                                        new_window.rcv_wup = new_migration_info->rev_wup;

                                        ast(setsockopt(rfd, IPPROTO_TCP, TCP_REPAIR_WINDOW, &new_window, sizeof(new_window)) == 0, "setsockopt7", NULL);
#ifdef WITH_TLS
#ifdef PROFILE
                                        struct timespec start_time11, end_time11;
                                        clock_gettime(CLOCK_MONOTONIC, &start_time11);
#endif /* PROFILE */
#ifdef WITH_KTLS
                                        /* deserialize ktls context and enable ktls */
                                        if (new_migration_info->buf.len > 0)
                                        {
                                                socklen_t optlen = sizeof(struct tls12_crypto_info_aes_gcm_256);

                                                struct tls12_crypto_info_aes_gcm_256 *crypto_info_send = new_migration_info->buf.data;
                                                struct tls12_crypto_info_aes_gcm_256 *crypto_info_recv = new_migration_info->buf.data + optlen;

                                                if (setsockopt(rfd, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) < 0)
                                                {
                                                        fprintf(stderr, "Couldn't set TCP_ULP option (%s)\n", strerror(errno));
                                                        exit(EXIT_FAILURE);
                                                }

                                                if (setsockopt(rfd, SOL_TLS, TLS_TX, crypto_info_send, optlen) < 0)
                                                {
                                                        fprintf(stderr, "Couldn't set TLS_TX option (%s)\n", strerror(errno));
                                                        exit(EXIT_FAILURE);
                                                }

                                                if (setsockopt(rfd, SOL_TLS, TLS_RX, crypto_info_recv, optlen) < 0)
                                                {
                                                        fprintf(stderr, "Couldn't set TLS_RX option (%s)\n", strerror(errno));
                                                        exit(EXIT_FAILURE);
                                                }

                                                fd_state[rfd].ktls_enabled = 1;
                                        }
#else  /* TLS */
                                        if (new_migration_info->buf.len > 0)
                                        {
                                                imported_context = tls_import_context(new_migration_info->buf.data, new_migration_info->buf.len);
                                                if (imported_context)
                                                {
                                                        fd_state[rfd].tls_context = imported_context;
                                                        tls_make_exportable(fd_state[rfd].tls_context, 1);
                                                }
                                                else
                                                {
                                                        perror("tls_import_context");
                                                        exit(0);
                                                }
                                        }
#endif /* WITH_KTLS */
#ifdef PROFILE
                                        clock_gettime(CLOCK_MONOTONIC, &end_time11);
                                        printf("deserialize tls: %.9lf\n", diff_timespec(&end_time11, &start_time11));
#endif /* PROFILE */
#endif /* WITH_TLS */
                                        /* quiting repair mode */
                                        ast(setsockopt(rfd, IPPROTO_TCP, TCP_REPAIR, &(int){-1}, sizeof(int)) == 0, "setsockopt8", NULL);
#ifdef PROFILE
                                        clock_gettime(CLOCK_MONOTONIC, &end_time2);
                                        printf("deserialize tcp + tls: %.9lf\n", diff_timespec(&end_time2, &start_time2));
#endif /* PROFILE */

                                        /* modify src ip on fake server */
                                        if (fd == control_fake_fds[worker_id])
                                        { // fake receiving handoff msg
#ifdef PROFILE
                                                clock_gettime(CLOCK_MONOTONIC, &start_time);
#endif /* PROFILE */
                                                key.src_ip = inet_addr(fake_my_ip);
                                                key.dst_ip = inet_addr(client_ip);
                                                key.src_port = htons(50000);
                                                key.dst_port = new_migration_info->peer_port;

                                                value.modify_src_ip = 1;
                                                value.new_src_ip = inet_addr(original_ip);
                                                ast(bpf_map_update_elem(egress_map, &key, &value, BPF_ANY) == 0, "error bpf_map_update_elem src ip modification", NULL);

#ifdef PROFILE
                                                clock_gettime(CLOCK_MONOTONIC, &end_time);
                                                printf("src ip modification ebpf: %.9lf\n", diff_timespec(&end_time, &start_time));
#endif /* PROFILE */
                                        }
                                        else
                                        {// original receiving handoff msg
                                                /* remove redirection & send end msg to fake */
#ifdef DO_EBPF
                                                key.src_ip = inet_addr(client_ip); // ebpf needs network byte order
                                                key.dst_ip = inet_addr(original_ip);
                                                key.src_port = new_migration_info->peer_port;
                                                key.dst_port = htons(50000);
#ifdef PROFILE
                                                clock_gettime(CLOCK_MONOTONIC, &start_time);
#endif /* PROFILE */
                                                ast(bpf_map_delete_elem(ingress_map, &key) == 0, "error bpf_map_delete_elem redirect1", NULL);
#ifdef PROFILE
                                                clock_gettime(CLOCK_MONOTONIC, &end_time);
                                                printf("remove redirection client -> original ebpf: %.9lf\n", diff_timespec(&end_time, &start_time));
#endif /* PROFILE */
#endif /* DO_EBPF */
#ifdef DO_TC
#ifdef DO_NBTC
#ifdef PROFILE
                                                clock_gettime(CLOCK_MONOTONIC, &start_time);
#endif /* PROFILE */
                                                int client_port = ntohs(new_migration_info->peer_port);
                                                if (!rule_in_queue(q, client_port))
                                                {
                                                        /* *********************************************************
                                                         * rule_in_queue() returns 0 if the rule is not in the queue
                                                         * if so, there are two cases:
                                                         * 1. the rule is offloaded, remove it synchronously immediately.
                                                         * 2. the rule was given up, no need to remove it.
                                                         * for both of two cases, call remove_redirection
                                                         * if it's case 1, remove_redirection will remove the rule synchronously.
                                                         * if it's case 2, remove_redirection will throw an error, 
                                                         * because the rull will not be found in the hash table
                                                         * 
                                                         * ?? or we can add a flag to indicate the rule was given up,
                                                         * ?? in which case, we don't have to call remove_redirection.
                                                         * 
                                                         * rule_in_queue() returns 1 if the rule is in the queue
                                                         * if so, it enables skip flat
                                                         * *********************************************************/
                                                        remove_redirection_str(
                                                                client_ip, original_ip,
                                                                ntohs(new_migration_info->peer_port), (uint16_t)50000);
                                                }
#ifdef PROFILE
                                                clock_gettime(CLOCK_MONOTONIC, &end_time);
                                                printf("remove redirection client -> original non-blocking tc: %.9lf\n", diff_timespec(&end_time, &start_time));
#endif /* PROFILE */
#else
#ifdef PROFILE
                                                clock_gettime(CLOCK_MONOTONIC, &start_time);
#endif /* PROFILE */
                                                ast(remove_redirection_str(
                                                        client_ip, original_ip,
                                                        ntohs(new_migration_info->peer_port), (uint16_t)50000) == 0,
                                                        "remove_redirection_str88", NULL);
#ifdef PROFILE
                                                clock_gettime(CLOCK_MONOTONIC, &end_time);
                                                printf("remove redirection client -> original tc: %.9lf\n", diff_timespec(&end_time, &start_time));
#endif /* PROFILE */
#endif /* DO_NBTC */
#endif /* DO_TC */
                                                // pack & send END to fake server asking removing blocking rule
                                                msg_type_info = (InfoToMigrate *)malloc(sizeof(InfoToMigrate));
                                                info_to_migrate__init(msg_type_info);

                                                msg_type_info->msg_type = END_MSG;
                                                msg_type_info->self_addr = new_migration_info->self_addr;
                                                msg_type_info->peer_addr = new_migration_info->peer_addr;
                                                msg_type_info->self_port = new_migration_info->self_port;
                                                msg_type_info->peer_port = new_migration_info->peer_port;

                                                proto_msg_len = info_to_migrate__get_packed_size(msg_type_info);
                                                proto_msg_buf = malloc(proto_msg_len);

                                                info_to_migrate__pack(msg_type_info, proto_msg_buf);

                                                // dealing with boundaries: adding length prefix
                                                net_proto_msg_len = htonl(proto_msg_len);
                                                combined_proto_msg_buf = malloc(sizeof(net_proto_msg_len) + proto_msg_len);
                                                memcpy(combined_proto_msg_buf, &net_proto_msg_len, sizeof(net_proto_msg_len));
                                                memcpy(combined_proto_msg_buf + sizeof(net_proto_msg_len), proto_msg_buf, proto_msg_len);

                                                len = write(fd, combined_proto_msg_buf, sizeof(net_proto_msg_len) + proto_msg_len);
                                                ast(len > 0, "write5", NULL);

                                                free(msg_type_info);
                                                free(combined_proto_msg_buf);
                                                free(proto_msg_buf);

                                                // update ctrl_conn's target fake server
                                                int old = fd_state[fd].target_fake_id;
                                                fd_state[rfd].target_fake_id = (fd_state[fd].target_fake_id + 1) % NUM_FAKE;
                                        } // end original receiving handoff msg

                                        epoll_add(epfd, rfd);

                                        /* send READY from fake to original */
                                        /* send OK from fake to client */
                                        if (fd == control_fake_fds[worker_id])
                                        { // fake receiving handoff, send READY to original
                                                msg_type_info = (InfoToMigrate *)malloc(sizeof(InfoToMigrate));
                                                info_to_migrate__init(msg_type_info);

                                                msg_type_info->msg_type = READY_MSG;
                                                msg_type_info->self_addr = 0;
                                                msg_type_info->peer_addr = 0;
                                                msg_type_info->self_port = rfd; // original send this rfd back to fake later and fake will use this rfd to send data to original
                                                msg_type_info->peer_port = new_migration_info->peer_port;

                                                proto_msg_len = info_to_migrate__get_packed_size(msg_type_info);
                                                proto_msg_buf = malloc(proto_msg_len);
                                                info_to_migrate__pack(msg_type_info, proto_msg_buf);

                                                // dealing with boundaries: adding length prefix
                                                net_proto_msg_len = htonl(proto_msg_len);
                                                combined_proto_msg_buf = malloc(sizeof(net_proto_msg_len) + proto_msg_len);
                                                memcpy(combined_proto_msg_buf, &net_proto_msg_len, sizeof(net_proto_msg_len));
                                                memcpy(combined_proto_msg_buf + sizeof(net_proto_msg_len), proto_msg_buf, proto_msg_len);
                                                len = write(fd, combined_proto_msg_buf, sizeof(net_proto_msg_len) + proto_msg_len);
                                                ast(len > 0, "write61", NULL);
                                                if (len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                                                        len = handle_ctrlfd_eagain(epfd, fd, combined_proto_msg_buf, proto_msg_len + sizeof(net_proto_msg_len), ctrl_msg_buf, ctrl_msg_len);

                                                free(proto_msg_buf);
                                                proto_msg_buf = NULL;
                                                if (len >= 0)
                                                {
                                                        free(combined_proto_msg_buf);
                                                        combined_proto_msg_buf = NULL;
                                                }
                                                free(new_migration_info);
                                                new_migration_info = NULL;
                                                free(msg_type_info);
                                                msg_type_info = NULL;

                                                /* response HTTP OK when DO_REPAIR is defined */
                                                continue;
                                        }
                                        else
                                        { // original receiving handoff, serialize new built tcp connection
                                                free(new_migration_info);
                                                fd = rfd;
                                                goto startover;
                                        }
                                } // end if(HANDOFF_MSG)

                                if (new_migration_info->msg_type == READY_MSG)
                                {
                                        if (fd == control_fake_fds[worker_id])
                                        { // fake receiving READY from original
                                                int to_be_responded_fd = new_migration_info->self_port;
                                                response_ok(to_be_responded_fd, epfd, httpbuf, httplen);
                                                continue;
                                        }
                                        else
                                        { // original receiving READY: remove blocking, insert redirection
#ifdef DO_EBPF
                                                // ebpf needs network byte order
                                                key.src_ip = inet_addr(client_ip);
                                                key.dst_ip = inet_addr(original_ip);
                                                key.src_port = new_migration_info->peer_port;
                                                key.dst_port = htons(50000);

                                                value.block = 0;
                                                value.redirect = 1;
                                                value.new_dst_ip = inet_addr(fake_ip[fd_state[fd].target_fake_id]);
                                                unsigned char mac[6];
                                                parse_mac(original_mac, mac);
                                                memcpy(value.new_src_mac, mac, sizeof(mac));
                                                parse_mac(fake_mac[fd_state[fd].target_fake_id], mac);
                                                memcpy(value.new_dst_mac, mac, sizeof(mac));
#ifdef PROFILE
                                                clock_gettime(CLOCK_MONOTONIC, &start_time);
#endif /* PROFILE */
                                                ast(bpf_map_update_elem(ingress_map, &key, &value, BPF_ANY) == 0, "error bpf_map_update_elem redirect", NULL);
#ifdef PROFILE
                                                clock_gettime(CLOCK_MONOTONIC, &end_time);
                                                printf("insert redirection client (unblocking at same time) -> original ebpf: %.9lf\n", diff_timespec(&end_time, &start_time));
#endif /* PROFILE */
#endif /* DO_EBPF */
#ifdef DO_TC
#ifdef DO_NBTC
#ifdef PROFILE
                                                clock_gettime(CLOCK_MONOTONIC, &start_time);
#endif /* PROFILE */
                                                rule_args *arg_r_c2o = (rule_args *)malloc(sizeof(rule_args));
                                                if (!arg_r_c2o)
                                                {
                                                        perror("Failed to allocate memory for arg_r_c2o");
                                                        exit(1);
                                                }
                                                arg_r_c2o->skip = 0;
                                                arg_r_c2o->src_ip = client_ip;
                                                arg_r_c2o->dst_ip = original_ip;
                                                arg_r_c2o->src_port = ntohs(new_migration_info->peer_port);
                                                arg_r_c2o->dst_port = (uint16_t)50000;
                                                arg_r_c2o->new_src_ip = client_ip;
                                                arg_r_c2o->new_src_mac = original_mac;
                                                arg_r_c2o->new_dst_ip = fake_ip[fd_state[fd].target_fake_id];
                                                arg_r_c2o->new_dst_mac = fake_mac[fd_state[fd].target_fake_id];
                                                arg_r_c2o->new_src_port = ntohs(new_migration_info->peer_port);
                                                arg_r_c2o->new_dst_port = (uint16_t)50000;
                                                arg_r_c2o->block = blocking_disabled;
                                                arg_r_c2o->hw_offload = hw_offload;

                                                /* lock, enqueue, unlock the queue,
                                                 * if the queue is full, just simply give up.
                                                 * rule_enqueue() returns 0 if the queue is full, 
                                                 * which means that the rule is not pushed into the queue,
                                                 * and therefore there is no hardware rule,
                                                 * so no need to do tc hw rule deletion later.
                                                 * rule_enqueue() returns 1 if the rule is successfully pushed into the queue,
                                                 * in this case, tc hw rule deletion is needed if this rule is not found in the queue 
                                                 */
                                                rule_enqueue(q, arg_r_c2o);
                                                free(arg_r_c2o);

#ifdef PROFILE
                                                clock_gettime(CLOCK_MONOTONIC, &end_time);
                                                printf("insert redirection client -> original non-blocking tc: %.9lf\n", diff_timespec(&end_time, &start_time));
#endif /* PROFILE */
#else /* DO_BLOCKING_TC */
#ifdef PROFILE
                                                clock_gettime(CLOCK_MONOTONIC, &start_time);
#endif /* PROFILE */
                                                ast(apply_redirection_str(
                                                        client_ip,
                                                        original_ip,
                                                        ntohs(new_migration_info->peer_port), (uint16_t)50000,

                                                        client_ip, original_mac,
                                                        fake_ip[fd_state[fd].target_fake_id], fake_mac[fd_state[fd].target_fake_id],
                                                        ntohs(new_migration_info->peer_port), (uint16_t)50000,
                                                        blocking_disabled, hw_offload)

                                                        == 0,
                                                    "apply_redirection_str7", NULL);
#ifdef PROFILE
                                                clock_gettime(CLOCK_MONOTONIC, &end_time);
                                                printf("insert redirection client -> original tc: %.9lf\n", diff_timespec(&end_time, &start_time));
#endif /* PROFILE */
#endif /* DO_NBTC */
#endif /* DO_TC */
                                                /* send READY to fake, telling fake that it can response OK */
                                                msg_type_info = (InfoToMigrate *)malloc(sizeof(InfoToMigrate));
                                                info_to_migrate__init(msg_type_info);

                                                msg_type_info->msg_type = READY_MSG;
                                                msg_type_info->self_addr = 0;
                                                msg_type_info->peer_addr = 0;
                                                msg_type_info->self_port = new_migration_info->self_port; // it's actually rfd
                                                msg_type_info->peer_port = 0;

                                                proto_msg_len = info_to_migrate__get_packed_size(msg_type_info);
                                                proto_msg_buf = malloc(proto_msg_len);
                                                info_to_migrate__pack(msg_type_info, proto_msg_buf);

                                                // dealing with boundaries: adding length prefix
                                                net_proto_msg_len = htonl(proto_msg_len);
                                                combined_proto_msg_buf = malloc(sizeof(net_proto_msg_len) + proto_msg_len);
                                                memcpy(combined_proto_msg_buf, &net_proto_msg_len, sizeof(net_proto_msg_len));
                                                memcpy(combined_proto_msg_buf + sizeof(net_proto_msg_len), proto_msg_buf, proto_msg_len);
                                                len = write(fd, combined_proto_msg_buf, sizeof(net_proto_msg_len) + proto_msg_len);
                                                //ast(len > 0, "write62", NULL);
                                                if (len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                                                len = handle_ctrlfd_eagain(epfd, fd, combined_proto_msg_buf, proto_msg_len + sizeof(net_proto_msg_len), ctrl_msg_buf, ctrl_msg_len);

                                                free(proto_msg_buf);
                                                proto_msg_buf = NULL;
                                                if (len >= 0)
                                                {
                                                        free(combined_proto_msg_buf);
                                                        combined_proto_msg_buf = NULL;
                                                }
                                                free(new_migration_info);
                                                new_migration_info = NULL;
                                                free(msg_type_info);
                                                msg_type_info = NULL;
                                                continue;
                                        } // end original receiving READY
                                } // end if(READY)

                                if (new_migration_info->msg_type == END_MSG)
                                {
                                        if (fd == control_fake_fds[worker_id])
                                        {
                                                if (new_migration_info->self_addr != 0)
                                                {// normal END: fake unblock & remove src ip modification
                                                        /* unblocking */
                                                        key.src_ip = inet_addr(client_ip); // ebpf needs network byte order
                                                        key.dst_ip = inet_addr(fake_my_ip);
                                                        key.src_port = new_migration_info->peer_port;
                                                        key.dst_port = htons(50000);
#ifdef PROFILE
                                                        clock_gettime(CLOCK_MONOTONIC, &start_time);
#endif /* PROFILE */
                                                        ast(bpf_map_delete_elem(ingress_map, &key) == 0, "error bpf_map_delete_elem unblock2", NULL);
#ifdef PROFILE
                                                        clock_gettime(CLOCK_MONOTONIC, &end_time);
                                                        printf("unblocking client -> fake ebpf: %.9lf\n", diff_timespec(&end_time, &start_time));
#endif /* PROFILE */

                                                        /* remove src ip modification */
#ifdef PROFILE
                                                        clock_gettime(CLOCK_MONOTONIC, &start_time);
#endif /* PROFILE */
                                                        key.src_ip = inet_addr(fake_my_ip); // ebpf needs network byte order
                                                        key.dst_ip = inet_addr(client_ip);
                                                        key.src_port = htons(50000);
                                                        key.dst_port = new_migration_info->peer_port;
                                                        ast(bpf_map_delete_elem(egress_map, &key) == 0, "error bpf_map_delete_elem src ip modification 1", NULL);
#ifdef PROFILE
                                                        clock_gettime(CLOCK_MONOTONIC, &end_time);
                                                        printf("remove src ip modification fake -> client tc: %.9lf\n", diff_timespec(&end_time, &start_time));
#endif /* PROFILE */
                                                }
                                                else
                                                { // fake receive TCP_CLOSE END_msg

                                                        /* remove src ip modification */
                                                        key.src_ip = inet_addr(fake_my_ip); // ebpf needs network byte order
                                                        key.dst_ip = inet_addr(client_ip);
                                                        key.src_port = htons(50000);
                                                        key.dst_port = new_migration_info->peer_port;
                                                        ast(bpf_map_delete_elem(egress_map, &key) == 0, "error bpf_map_delete_elem src ip modification 2", NULL);
                                                        printf("fake receive END due to TCP_CLOSE fd, removing src ip modification rule: not existed\n");
                                                        // else
                                                        //         printf("fake receive END due to TCP_CLOSE fd, removing src ip modification rule: not existed\n");
                                                }
                                        }
                                        else
                                        { // original receive TCP_CLOSE END_msg: remove redirection
                                          // &send END to fake asking remove src ip modification
                                                // printf("TCP_CLOSE END\n");
                                                int closed_fd = new_migration_info->self_addr;

                                                /* remove redirection */
#ifdef DO_EBPF
                                                key.src_ip = inet_addr(client_ip);
                                                key.dst_ip = inet_addr(original_ip);
                                                // new_migration_info->self_addr now is actually fd
                                                // int closed_fd = new_migration_info->self_addr;
                                                key.src_port = fd_state[closed_fd].tuple.src_port;
                                                key.dst_port = htons(50000);
                                                ast(bpf_map_delete_elem(ingress_map, &key) == 0, "error bpf_map_delete_elem redirect, original receive TCP_CLOSE END", NULL);
                                                // bpf_map_delete_elem(ingress_map, &key);
#endif /* DO_EBPF */
#ifdef DO_TC
#ifdef DO_NBTC
                                                int client_port = ntohs(fd_state[closed_fd].tuple.src_port);
                                                if (!rule_in_queue(q, client_port))
                                                {
                                                        remove_redirection_str(
                                                                client_ip, original_ip,
                                                                ntohs(fd_state[closed_fd].tuple.src_port), (uint16_t)50000);
                                                }
#else
                                                ast(remove_redirection_str(
                                                        client_ip, original_ip,
                                                        ntohs(fd_state[new_migration_info->self_addr].tuple.src_port), (uint16_t)50000) == 0,
                                                    "remove_redirection_str08", NULL);
#endif /* DO_NBTC */
#endif /* DO_TC */
                                                /* send END to fake asking remove src ip modification */
                                                msg_type_info = (InfoToMigrate *)malloc(sizeof(InfoToMigrate));
                                                info_to_migrate__init(msg_type_info);

                                                msg_type_info->msg_type = END_MSG;
                                                // set self_port as 0 if don't want fake to do unblocking
                                                msg_type_info->self_addr = 0;
                                                msg_type_info->peer_addr = 0;
                                                msg_type_info->self_port = 0;
                                                msg_type_info->peer_port = fd_state[closed_fd].tuple.src_port;

                                                proto_msg_len = info_to_migrate__get_packed_size(msg_type_info);
                                                proto_msg_buf = malloc(proto_msg_len);

                                                info_to_migrate__pack(msg_type_info, proto_msg_buf);

                                                // dealing with boundaries: adding length prefix
                                                net_proto_msg_len = htonl(proto_msg_len);
                                                combined_proto_msg_buf = malloc(sizeof(net_proto_msg_len) + proto_msg_len);
                                                memcpy(combined_proto_msg_buf, &net_proto_msg_len, sizeof(net_proto_msg_len));
                                                memcpy(combined_proto_msg_buf + sizeof(net_proto_msg_len), proto_msg_buf, proto_msg_len);

                                                ssize_t len = write(fd, combined_proto_msg_buf, sizeof(net_proto_msg_len) + proto_msg_len);
                                                ast(len > 0, "write8", NULL);

                                                free(msg_type_info);
                                                free(combined_proto_msg_buf);
                                                free(proto_msg_buf);
                                                memset(&fd_state[closed_fd], 0, sizeof(connection_table));
                                        }
                                        continue;
                                } // end if(END)
                        } // end if (control)
#else  /* DO_REPAIR is not defined */

                                /* response HTTP OK if DO_REPAIR is not defined*/
                                response_ok(fd, epfd, httpbuf, httplen);
                                continue;
                        }
#endif /* DO_REPAIR */
                } // end for(events)
        } // end while(1)
} // end worker_fun()

int main(int argc, char **argv)
{
#ifdef DO_REPAIR
        /* initialization for tc redirection */
        if (argc < 7)
        {// argc == 7 means one fake server, 8 means two fake servers, and so on ...
                fprintf(stderr, "Usage: %s [device] "
                                "[ingress class parent] [egress class parent] "
                                "[client_machine_id] [original_server_id] "
                                "[fake_server_1_id] [fake_server_2_id] ... \n",
                        argv[0]);
                exit(1);
        }
        if (argc != NUM_FAKE + 6 + 2 + 2)
        {
                fprintf(stderr, "Number of fake servers is incorrect\n");
                exit(1);
        }
        ast(init_forward(argv[1], argv[2], argv[3]) >= 0, "init_forward error [device] [ingress] [egress]", NULL);
        printf("get command line arguments argc %d\n", argc);

        for (int i = 1; i < argc; i++)
        {
                if (strcmp(argv[i], "--content_size") == 0 && i + 1 < argc)
                {
                        CONTENT_SIZE = atoi(argv[++i]);
                }
#ifdef DO_FREQUENCY
                else if (strcmp(argv[i], "--migration_frequency") == 0 && i + 1 < argc)
                {
                        MIGRATION_FREQUENCY = atoi(argv[++i]);
                }
#endif /* DO_FREQUENCY */
        }

        /* setting up machine info*/
        char line[256], s1[10], s2[20], s3[20];
        FILE *fpointer;
        fpointer = fopen("config", "r");
        ast(fpointer > 0, "fopen", NULL);
        if (fpointer)
        {
                while (fgets(line, 256, fpointer) != NULL)
                {// scan every line in the config file
                        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') // skip comments and blank lines
                                continue;
                        ast(sscanf(line, "%s %s %s", s1, s2, s3) == 3, "sscanf", NULL);
                        if (strcmp(s1, "tc") == 0)
                        { // current line matched tc, next line
                                if (strcmp(s2, "sw") == 0)
                                        hw_offload = false;
                                else
                                        hw_offload = true;
                                continue;
                        }
                        if (strcmp(s1, argv[4]) == 0)
                        { // current line matched client, next line
                                strcpy(client_ip, s2);
                                strcpy(client_mac, s3);
                                continue;
                        }
                        if (strcmp(s1, argv[5]) == 0)
                        { // current line matched original, next line
                                strcpy(original_ip, s2);
                                strcpy(original_mac, s3);
                                continue;
                        }
                        for (int i = 0; i < NUM_FAKE; i++)
                        {
                                if (strcmp(s1, argv[6 + i]) == 0)
                                { // current line matched one of the fakes, skip for loop
                                        strcpy(fake_ip[i], s2);
                                        strcpy(fake_mac[i], s3);
                                        break;
                                }
                        }
                        continue; // no match or match one of the fake, next line
                }
        }
        fclose(fpointer);

        /* open ebpf map */
        ingress_map = bpf_obj_get("/sys/fs/bpf/ebpf_redirect_block/map");
        ast(ingress_map >= 0, "Failed to open BPF ingress map\n", NULL);
        egress_map = bpf_obj_get("/sys/fs/bpf/ebpf_modify_srcip/map");
        ast(egress_map >= 0, "Failed to open BPF egress map\n", NULL);

#endif /* DO_REPAIR */

        /* preparing http responding content */
        httpbuf = malloc((HTTPHDR_LEN + 20 + CONTENT_SIZE) * sizeof(char));
        char *content = calloc(CONTENT_SIZE, sizeof(char));
        if (content == NULL)
        {
                perror("Failed to allocate memory for content");
                exit(0);
        }
        httphdrlen = generate_httphdr(CONTENT_SIZE, httpbuf);
        memcpy(httpbuf + httphdrlen, content, CONTENT_SIZE);
        httplen = httphdrlen + CONTENT_SIZE;
        free(content);

        signal(SIGPIPE, SIG_IGN);

        /* data socket */
        int data_so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ast(data_so > 0, "data_so", NULL);
        reuseaddr(data_so);
        ioctl(data_so, FIONBIO, &(int){1});
        ast(setsockopt(data_so, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) == 0, "data setsockopt", NULL);
        ast(setsockopt(data_so, IPPROTO_TCP, TCP_QUICKACK, &(int){1}, sizeof(int)) == 0, "data setsockopt", NULL);

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(50000);

        ast(bind(data_so, (struct sockaddr *)&addr, sizeof(addr)) == 0, "data bind", NULL);
        ast(listen(data_so, 5) == 0, "data listen", NULL);

        printf("Server listening on port 50000...\n");
        printf("Ready for connections.\n");

#ifdef WITH_TLS
        tls_init();
#endif /* WITH_TLS */

#ifdef DO_NBTC
        /* initialize rule queue */
        q = malloc(sizeof(rule_queue_t));
        if (!q)
        {
                perror("Failed to allocate memory for rule queue");
                exit(EXIT_FAILURE);
        }
        rule_queue_init(q, Q_SIZE);
#endif /* DO_NBTC */

        /* create threads */
        pthread_t workers[NUM_THREADS];
        socket_info *sock_info;

        for (int i = 0; i < NUM_THREADS; i++)
        {
                sock_info = malloc(sizeof(socket_info));
                sock_info->data_socket = data_so;
                sock_info->worker_id = i;

                pthread_create(&workers[i], NULL, worker_func, sock_info);

                /* set cpu affieuenity */
                cpu_set_t cpuset;
                CPU_ZERO(&cpuset);
                CPU_SET(i, &cpuset);

                int rc = pthread_setaffinity_np(workers[i], sizeof(cpu_set_t), &cpuset);
                if (rc != 0)
                {
                        printf("Error calling pthread_setaffinity_np: %d\n", rc);
                        exit(0);
                }
        }
#ifdef DO_NBTC
        /* create the consumer thread */
        pthread_t rule_consumer;
        pthread_create(&rule_consumer, NULL, rule_q_consumer, q);
        /* set cpu for the consumer thread */
        cpu_set_t cpuset_consumer;
        CPU_ZERO(&cpuset_consumer);
        CPU_SET(19, &cpuset_consumer);
        int rc = pthread_setaffinity_np(rule_consumer, sizeof(cpu_set_t), &cpuset_consumer);
        if (rc != 0)
        {
                printf("Error calling pthread_setaffinity_np: %d\n", rc);
                exit(0);
        }
#endif /* DO_NBTC */

        for (int i = 0; i < NUM_THREADS; i++)
        {
                pthread_join(workers[i], NULL);
                free(sock_info);
        }
#ifdef DO_NBTC
        /* consumer thread */
        pthread_join(rule_consumer, NULL);
#endif /* DO_NBTC */

        /* cleanup */
        close(data_so);
        free(httpbuf);
#ifdef DO_REPAIR
        close(ingress_map);
        close(egress_map);
#ifdef DO_NBTC
        rule_queue_destroy(q);
#endif /* DO_NBTC */
#endif /* DO_REPAIR */

        return 0;
}