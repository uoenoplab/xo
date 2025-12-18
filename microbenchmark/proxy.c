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

#define MAC_ADDRSTRLEN 20

#ifdef PROFILE
#include <time.h>
// https://stackoverflow.com/questions/68804469/subtract-two-timespec-objects-find-difference-in-time-or-duration
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

struct timespec start_time, end_time;
#endif /* PROFILE */

#define CONTENT_SIZE 8*1024*1024
#define HTTPHDR_LEN 81
static char *HTTPHDR = (char *)"HTTP/1.1 200 OK\r\n"
                        "Connection: keep-alive\r\n"
                        "Server: Apache/2.2.800\r\n"
                        "Content-Length: ";
#define NUM_FAKE 4
#define NUM_THREADS 8
#define CONN_POOL_SIZE 20

struct connection_pool
{// only for proxy-backend connections
        int conn_fd[CONN_POOL_SIZE]; // proxy-backend connections
        bool is_available[CONN_POOL_SIZE]; 
        int client_fd[CONN_POOL_SIZE]; // client for which the proxy-backend connection is currently serving
};

/* global variables */
struct connection_pool conn_pool[NUM_FAKE][NUM_THREADS]; // connection pools for each thread
int designated_thread = 0; // ensure control connection is handled by the designated thread
char *httpbuf;
ssize_t httplen, httphdrlen;
int offset_read[2048] = {0};
int offset_write[2048] = {0};

// machine info
char client_ip[INET_ADDRSTRLEN], client_mac[MAC_ADDRSTRLEN];
char original_ip[INET_ADDRSTRLEN], original_mac[MAC_ADDRSTRLEN];
char fake_ip[NUM_FAKE][INET_ADDRSTRLEN], fake_mac[NUM_FAKE][MAC_ADDRSTRLEN];

typedef struct
{
        int data_socket;
        int worker_id;
}socket_info;

ssize_t
generate_httphdr(size_t content_length, char *buf)
{
        char *c = buf;
        c = mempcpy(c, HTTPHDR, HTTPHDR_LEN);
        c += sprintf(c, "%lu\r\n\r", content_length);
        *c++ = '\n';
        return c - buf;
}

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

static void
epoll_add(int epfd, int fd)
{
	struct epoll_event ev;//used for epoo_ctl()
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
	ast(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int))
		       	== 0, "setsockopt9", NULL);
	ast(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int))
			== 0, "setsockopt10", NULL);
}

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

void parse_mac(const char* mac_str, unsigned char* mac)
{// used in ebpf rule insertion
        int values[6];
        if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x", 
                                &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]) == 6)
                for (int i = 0; i < 6; ++i)
                        mac[i] = (uint8_t) values[i];
        else
        {
                printf("sscanf in parse_mac error\n");
                exit(0);
        }
}
#ifdef WITH_TLS
void close_fd_cleanup(int fd, int epfd, struct TLSContext *context)
#else
void close_fd_cleanup(int fd, int epfd)
#endif /* WITH_TLS */
{
	ast(epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL) == 0, "epoll_ctl close_fd_cleanup", NULL);
        close(fd);
#ifdef WITH_TLS
        if (context)
        {
                tls_destroy_context(context);
                context = NULL;
        }
#endif /* WITH_TLS */
}

int get_available_conn(int fake_id, int worker_id)
{// from proxy-backend connection pool
        for (int i = 0; i < CONN_POOL_SIZE; i++)
        {
                if (conn_pool[fake_id][worker_id].is_available[i])
                        return i;
        }
        return -1;
}

void * worker_func(void *arg)
{
int fake_id = 0;

        /* create epoll */
        int epfd = epoll_create(1024);
        ast (epfd > 0, "epoll_create", NULL);
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
        struct TLSContext *contexts[2048];
#endif /* WITH_TLS */

        /* process ctrl_so on both proxy and backend */
        int port = 60000 + worker_id; // each thread has its own control port
        struct sockaddr_in ctrl_sin;
        ctrl_sin.sin_family = AF_INET;
        ctrl_sin.sin_port = htons(port);
        ctrl_sin.sin_addr.s_addr = INADDR_ANY;

        int ctrl_so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ast(ctrl_so > 0, "ctrl_so socket()", NULL);
        reuseaddr(ctrl_so);
        ioctl(ctrl_so, FIONBIO, &(int){1});

        ast(bind(ctrl_so, (struct sockaddr *)&ctrl_sin, sizeof(ctrl_sin)) == 0, "ctrl_so bind()", NULL);
        ast(listen(ctrl_so, 20) == 0, "ctrl_so listen()", NULL);

        epoll_add(epfd, ctrl_so);

        bool is_conn_pool_initialized = false; // used on proxy
        int conn_pool_index = 0; // used on backend when accept new proxy-backend connection in the pool
        int is_client_conn[2048] = {-1};// distinguish client connection or proxy-backend connection
        int is_backend[2048] = {-1};// distinguish backend or proxy

        while(1)
        {
                int n = epoll_wait(epfd, events, 1024, 2000);
                ast (n >= 0, "epoll_wait", NULL);
                //printf("threadid: %lu just after epoll_wait %d\n", (unsigned long)pthread_self(), n);

                for (int i = 0; i < n; i++)
                {
                        int fd = events[i].data.fd;

                        if (events[i].events & EPOLLERR)
                        {
#ifdef WITH_TLS
                                close_fd_cleanup(fd, epfd, contexts[fd]);
#else
                                close_fd_cleanup(fd, epfd);
#endif /* WITH_TLS */
                                continue;
                        }

                        if (events[i].events & EPOLLOUT)
                        {
                                ssize_t len_write = 0;
                                while ((len_write = write(fd, httpbuf + offset_write[fd], httplen - offset_write[fd])) > 0)
                                {
                                        offset_write[fd] += len_write;
                                        if (offset_write[fd] == httplen)
                                        {// reset offset_write when done with writing entire OK
                                                offset_write[fd] = 0;

                                                struct epoll_event event;
                                                event.events = EPOLLIN | EPOLLERR;
                                                event.data.fd = fd;
                                                ast(epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &event)==0, "epoll_ctl in epoll modification", NULL);

                                                break;
                                        }
                                }
                                if (offset_write[fd] > 0)
                                        continue; // partial write, wait for next EPOLLOUT
                               
                                continue;
                        }

                        if (fd == data_so) // data_so binded with 50000
                        {// proxy receives new connect request from client
                                struct sockaddr_in client_sin;
                                socklen_t slen = sizeof(client_sin);

                                int data_socket = accept(data_so, (struct sockaddr *)&client_sin, &slen);
                                if (data_socket == -1)
                                {
                                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                                                continue;
                                        else
                                        {
                                                perror("data accept");
                                                exit(0);
                                        }
                                }

                                reuseaddr(data_socket);
                                ioctl(data_socket, FIONBIO, &(int){1});
                                epoll_add(epfd, data_socket);

                                ast(setsockopt(data_socket, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) == 0, 
                                                "setsockopt TCP_NODELAY1", NULL);
                                ast(setsockopt(data_socket, IPPROTO_TCP, TCP_QUICKACK, &(int){1}, sizeof(int)) == 0, 
                                                "setsockopt TCP_QUICKACK1", NULL);

                                is_client_conn[data_socket] = 1;
                                is_backend[data_socket] = 0;

                                continue;
                        }

                        if (fd == ctrl_so) // ctrl_so binded with 60000 + worker_id
                        {// backend receives new connection
                                struct sockaddr_in ctrl_client_sin;
                                socklen_t slen = sizeof(ctrl_client_sin);

                                if (worker_id != designated_thread)// not the designated thread
                                        continue;

                                /* accept proxy-backend connection */
                                conn_pool[0][worker_id].conn_fd[conn_pool_index] = accept(ctrl_so, (struct sockaddr *)&ctrl_client_sin, &slen);
                                ast(conn_pool[0][worker_id].conn_fd[conn_pool_index] > 0, "accept backend", NULL);

                                reuseaddr(conn_pool[0][worker_id].conn_fd[conn_pool_index]);
                                ioctl(conn_pool[0][worker_id].conn_fd[conn_pool_index], FIONBIO, &(int){1});
                                ast(setsockopt(conn_pool[0][worker_id].conn_fd[conn_pool_index], IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) == 0, 
                                                "setsockopt TCP_NODELAY1", NULL);
                                ast(setsockopt(conn_pool[0][worker_id].conn_fd[conn_pool_index], IPPROTO_TCP, TCP_QUICKACK, &(int){1}, sizeof(int)) == 0, 
                                                "setsockopt TCP_QUICKACK1", NULL);
                                epoll_add(epfd, conn_pool[0][worker_id].conn_fd[conn_pool_index]);

                                /* initialize connection pool */
                                conn_pool[0][worker_id].is_available[conn_pool_index] = true;
                                conn_pool[0][worker_id].client_fd[conn_pool_index] = 0;

                                is_client_conn[conn_pool[0][worker_id].conn_fd[conn_pool_index]] = 0;
                                is_backend[conn_pool[0][worker_id].conn_fd[conn_pool_index]] = 1;

                                designated_thread = (designated_thread + 1) % NUM_THREADS;
                                conn_pool_index++;

                                continue;
                        }

                        if (is_client_conn[fd] == 1)
                        {// proxy receive GET, forward to backend
                                /* initialize proxy-backend connection pool */
                                if (!is_conn_pool_initialized)
                                {// do this only once and only on proxy, connect() to backend
                                        for (int j = 0; j < NUM_FAKE; j++)
                                        {
                                                for (int i = 0; i < CONN_POOL_SIZE; i++)
                                                {
                                                        struct sockaddr_in backend_sin;
                                                        backend_sin.sin_family = AF_INET;
                                                        backend_sin.sin_port = htons(port); // 60000 + worker_id
                                                        backend_sin.sin_addr.s_addr = inet_addr(fake_ip[j]);

                                                        conn_pool[j][worker_id].conn_fd[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                                                        ast(conn_pool[j][worker_id].conn_fd[i] > 0, "socket for conn_pool.conn_fd[i]", NULL);

                                                        ast(connect(conn_pool[j][worker_id].conn_fd[i], (struct sockaddr *)&backend_sin, sizeof(backend_sin)) == 0, 
                                                                        "connect backend", NULL);

                                                        epoll_add(epfd, conn_pool[j][worker_id].conn_fd[i]);
                                                        ioctl(conn_pool[j][worker_id].conn_fd[i], FIONBIO, &(int){1});
                                                        ast(setsockopt(conn_pool[j][worker_id].conn_fd[i], IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) == 0, 
                                                                        "setsockopt TCP_NODELAY3", NULL);
                                                        ast(setsockopt(conn_pool[j][worker_id].conn_fd[i], IPPROTO_TCP, TCP_QUICKACK, &(int){1}, sizeof(int)) == 0, 
                                                                        "setsockopt TCP_QUICKACK3", NULL);

                                                        conn_pool[j][worker_id].is_available[i] = true;
                                                        conn_pool[j][worker_id].client_fd[i] = 0;

                                                        is_client_conn[conn_pool[j][worker_id].conn_fd[i]] = 0;
                                                        is_backend[conn_pool[j][worker_id].conn_fd[i]] = 0;
                                                }
                                        }
                                        is_conn_pool_initialized = true;
                                }

                                /* get available proxy-backend connection */
                                int conn_index = get_available_conn(fake_id, worker_id);
                                ast(conn_index < CONN_POOL_SIZE * NUM_FAKE, "conn_index < CONN_POOL_SIZE * NUM_FAKE", NULL);
                                if (conn_index == -1) // No available proxy-backend connection in the pool
                                        continue;
                                
                                /* occupy proxy-backend connection */
                                conn_pool[fake_id][worker_id].is_available[conn_index] = false;
                                conn_pool[fake_id][worker_id].client_fd[conn_index] = fd;
                                // start now, this p-b connection only serves client fd
                                // release it when proxy done with forwarding OK to client fd

                                /* proxy read GET from client */
                                char buf[65533];
                                ssize_t len_read = read(fd, buf, sizeof(buf));
                                if (len_read <= 0)
                                {// handle error
                                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                                                continue;
                                        else if (errno == EPIPE || len_read == 0)
                                        {
#ifdef WITH_TLS
                                                close_fd_cleanup(fd, epfd, contexts[fd]);
#else
                                                close_fd_cleanup(fd, epfd);
#endif /* WITH_TLS */
                                                conn_pool[fake_id][worker_id].is_available[conn_index] = true;
                                                conn_pool[fake_id][worker_id].client_fd[conn_index] = 0;
                                                continue;
                                        }
                                        else
                                        {
                                                perror("proxy read() get from client");
                                                exit(0);
                                        }
                                }
#ifdef WITH_TLS
                                /* Establishing TLS */
                                if (!contexts[fd])
                                {
                                        contexts[fd] = tls_accept(server_context);
                                        tls_request_client_certificate(contexts[fd]);
                                        tls_make_exportable(contexts[fd], 1);
                                        /* receive client hello */
                                        handshake_reading(contexts[fd], buf, len_read, fd);
                                        /* send server hello */
                                        send_pending(fd, contexts[fd]);
                                        conn_pool[fake_id][worker_id].is_available[conn_index] = true;
                                        conn_pool[fake_id][worker_id].client_fd[conn_index] = 0;
                                        continue;
                                } 
                                else if (tls_established(contexts[fd]) != 1) 
                                {
                                        /* receive new key from client */
                                        handshake_reading(contexts[fd], buf, len_read, fd);
                                        /* server send finish message */ 
                                        send_pending(fd, contexts[fd]);
                                        if (!tls_established(contexts[fd]))
                                        {
                                                conn_pool[fake_id][worker_id].is_available[conn_index] = true;
                                                conn_pool[fake_id][worker_id].client_fd[conn_index] = 0;
			        		continue;
                                        }
                                        /* make ktls */
                                        if (tls_established(contexts[fd]) == 1)
                                                ast(tls_make_ktls(contexts[fd], fd) == 0, "tls_make_ktls in tls establishment", NULL);
                                }
#endif /* WITH_TLS */
                                /* proxy forward GET to backend, wait for backend response */
                                ssize_t len_write = write(conn_pool[fake_id][worker_id].conn_fd[conn_index], buf, len_read);
                                ast(len_write > 0, "write to backend", NULL);

                                fake_id = (fake_id + 1) % NUM_FAKE;

                                continue;
                        }//end if (proxy receives GET and forward to backend)

                        if (is_client_conn[fd] == 0 && is_backend[fd] == 1)
                        {// backend receive forwarded GET, respond OK to proxy
                                /* read forwarded GET from client */
                                char buf[65533];
                                ssize_t len_read = read(fd, buf, sizeof(buf));
                                if (len_read <= 0)
                                {// handle error
                                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                                                continue;
                                        else if (errno == EPIPE || len_read == 0)
                                        {
#ifdef WITH_TLS
                                                close_fd_cleanup(fd, epfd, contexts[fd]);
#else
                                                close_fd_cleanup(fd, epfd);
#endif /* WITH_TLS */
                                                continue;
                                        }
                                        else
                                        {
                                                perror("proxy read() get from client");
                                                exit(0);
                                        }
                                }

                                /* respond OK to proxy */
                                ssize_t len_write = 0;
                                while ((len_write = write(fd, httpbuf + offset_write[fd], httplen - offset_write[fd])) > 0)
                                {
                                        offset_write[fd] += len_write;
                                        if (offset_write[fd] == httplen)
                                        {// no partial write, do not need to change epoll flag
                                                offset_write[fd] = 0;
                                                break;
                                        }
                                }
                                if (offset_write[fd] > 0)
                                {// partial write, add epollout to fd
                                        struct epoll_event event;
                                        event.events = EPOLLOUT;
                                        event.data.fd = fd;
                                        ast(epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &event)==0, "epoll_ctl in epoll modification", NULL);
                                }

                                continue;
                        }//end: backend receives forwarded GET and respond OK to proxy

                        if (is_client_conn[fd] == 0 && is_backend[fd] == 0)
                        {// proxy receive OK from backend
                                /* retrieve OK from backend */
                                char buf[65533];
                                ssize_t len_read = 0;
                                int client_fd, conn_index, fake_index;
                                while ((len_read = read(fd, buf, (httplen - offset_read[fd]) < sizeof(buf) ? (httplen - offset_read[fd]) : sizeof(buf))) > 0)
                                {
                                        offset_read[fd] += len_read;
                                        if (offset_read[fd] == httplen)
                                        {// done with retrieving entire OK
                                                /* reset offset_read */
                                                offset_read[fd] = 0;

                                                /* look up conn_pool_index of current occupied connection */
                                                for (int j = 0; j < NUM_FAKE; j++)
                                                {
                                                        for (int i = 0; i < CONN_POOL_SIZE; i++)
                                                        {
                                                                if (conn_pool[j][worker_id].conn_fd[i] == fd)
                                                                {
                                                                        conn_index = i;
                                                                        fake_index = j;
                                                                        break;
                                                                }
                                                        }
                                                }
                                                /* temporarily keep client_fd */
                                                client_fd = conn_pool[fake_index][worker_id].client_fd[conn_index];

                                                /* release occupied connection in the pool */
                                                conn_pool[fake_index][worker_id].client_fd[conn_index] = 0;
                                                conn_pool[fake_index][worker_id].is_available[conn_index] = true;

                                                break;
                                        }
                                }
                                if (offset_read[fd] > 0) // partial read
                                        continue; // wait for next EPOLLIN
                                /* forwarded OK to client when done with retrieving entire OK */
                                ssize_t len_write = 0;
                                while ((len_write = write(client_fd, httpbuf + offset_write[client_fd], httplen - offset_write[client_fd])) > 0)
                                {
                                        offset_write[client_fd] += len_write;
                                        if (offset_write[client_fd] == httplen)
                                        {// no partial write, do not need to change epoll flag
                                                offset_write[client_fd] = 0;
                                                break;
                                        }
                                }
                                if (offset_write[client_fd] > 0)
                                {// partial write, add epollout to fd
                                        struct epoll_event event;
                                        event.events = EPOLLOUT | EPOLLERR;
                                        event.data.fd = client_fd;
                                        ast(epoll_ctl(epfd, EPOLL_CTL_MOD, client_fd, &event)==0, "epoll_ctl in epoll modification", NULL);
                                }
                                continue;
                        }//end proxy receives OK from backend
                }//end for(epoll_events)
        }//end while(1)
} //end worker_fun()


int main(int argc, char **argv)
{
        /* setting up machine info */
        FILE * fpointer;
        char line[50], s1[10], s2[20], s3[20];
        fpointer = fopen("config", "r");
        ast(fpointer > 0, "fopen", NULL);
        if (fpointer)
        {
                while (fgets(line, 50, fpointer) != NULL) 
                {
                        if (line[0] == '#')
                                continue;
                        ast(sscanf(line, "%s %s %s", s1, s2, s3) == 3, "sscanf", NULL);
                        if (strcmp(s1, argv[1]) == 0) 
                        {
                                strcpy(client_ip, s2);
                                strcpy(client_mac, s3);
                                continue;
                        }
                        if (strcmp(s1, argv[2]) == 0) 
                        {
                                strcpy(original_ip, s2);
                                strcpy(original_mac, s3);
                                continue;
                        }
                        for (int i = 0; i < NUM_FAKE; i++)
                        {
                                if (strcmp(s1, argv[3 + i]) == 0) 
                                {
                                        strcpy(fake_ip[i], s2);
                                        strcpy(fake_mac[i], s3);
                                        break;
                                }
                        }
                        continue;
                }
        }
        fclose(fpointer);

        signal(SIGPIPE, SIG_IGN);

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

        /* data socket */
        int data_so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ast(data_so > 0, "data_so", NULL);
        reuseaddr(data_so);
        ioctl(data_so, FIONBIO, &(int){1});

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(50000);

        ast(bind(data_so, (struct sockaddr *)&addr, sizeof(addr)) == 0, "data bind", NULL);
        ast(listen(data_so, 5) == 0, "data listen", NULL);

        /* create threads */
        pthread_t workers[NUM_THREADS];
        socket_info* sock_info;

        for (int i = 0; i < NUM_THREADS; i++)
        {
                sock_info = malloc(sizeof(socket_info));
                sock_info->data_socket = data_so;
                sock_info->worker_id = i;

                pthread_create(&workers[i], NULL, worker_func, sock_info);

                /* set cpu affinity */
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
        for (int i = 0; i < NUM_THREADS; i++)
        {
                pthread_join(workers[i], NULL);
                free(sock_info);
        }

        /* cleanup */
        close(data_so);
        free(httpbuf);

        return 0;
}