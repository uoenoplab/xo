#ifndef __HANDOFF_H__
#define __HANDOFF_H__

//#include <ngx_core.h>
//#include <ngx_config.h>
#include <ngx_connection.h>
//#include <ngx_http.h>
//extern struct ngx_http_request_t;

#include "queue.h"
#include "forward.h"
#include "ebpf_forward.h"

#include "http_client.h"
//#include <hiredis/hiredis.h>

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

#define HANDOFF_CTRL_PORT 9000

#define S3_HTTP_PORT 8080

//#include "zlog.h"

//extern zlog_category_t *zlog_handoff;
extern bool use_tc;
extern bool tc_offload;
extern bool tc_hybrid;
#define Q_SIZE 1000
extern rule_queue_t *q;


#define MAX_PEERS 4

typedef struct {
    char ifname[64];
    struct sockaddr_in my_sockaddr;
    uint8_t my_mac[6];

    struct sockaddr_in peer_sockaddr[MAX_PEERS];
    int num_peers;
    int my_id;
    //redisContext *redis_ctx;
    uint8_t *shmaddr;

    int handoff_freq;
    int handoff_back_counter;
    long int last_trigger;
} ngx_http_handoff_main_conf_t;


enum {
        HANDOFF_REQUEST,
        HANDOFF_BACK_REQUEST,
        HANDOFF_RESET_REQUEST,
        HANDOFF_DONE
};

struct handoff_in {
	uint32_t epoll_data_u32;
	int epoll_fd;
	int fd;
        int osd_arr_index;
        int thread_id;
        uint8_t *recv_protobuf;
        uint32_t recv_protobuf_len;
        uint32_t recv_protobuf_received;
        uint8_t *send_protobuf;
        uint32_t send_protobuf_len; // include header uint32 size
        uint32_t send_protobuf_sent;
	//rados_ioctx_t data_io_ctx;
	//rados_ioctx_t bucket_io_ctx;
        struct http_client *client_to_handoff_again;
        bool wait_for_originaldone;
        struct http_client *client_for_originaldone;

        ngx_connection_t *restored_conn;
        ngx_http_handoff_main_conf_t *ngx_conf;
        ngx_event_handler_pt original_write_handler;

        struct sockaddr_in frontend_sockaddr;
        int req_counter;
};

struct handoff_out_req;

struct handoff_out_queue {
    int num_requests;
    struct handoff_out_req* front;
    struct handoff_out_req* rear;
};

#define MAX_HANDOFF_OUT_RECONNECT 5

struct handoff_out {
	uint32_t epoll_data_u32;
	int epoll_fd;
	int fd;
        bool is_fd_connected;
        bool is_fd_in_epoll;
        int reconnect_count;
        //int osd_arr_index;
        int thread_id;
        struct handoff_out_queue *queue;
        // handoff out request currently sending out, deququed from queue
        struct http_client *client;
        uint8_t *recv_protobuf;
        uint32_t recv_protobuf_len;
        uint32_t recv_protobuf_received;
	ngx_http_handoff_main_conf_t *ngx_conf;
 //       ngx_http_request_t *req_to_free;
        void *req_to_free;
};

void handoff_out_serialize_reset(struct http_client *client, ngx_log_t *log);
void handoff_out_serialize(struct http_client *client, ngx_log_t *log);

//void handoff_out_connect(struct handoff_out *out_ctx);
//int handoff_out_reconnect(struct handoff_out *out_ctx);
//void handoff_out_issue(int epoll_fd, uint32_t epoll_data_u32, struct http_client *client,
//	struct handoff_out *out_ctx, int osd_arr_index, int thread_id);
//void handoff_out_issue_urgent(int epoll_fd, uint32_t epoll_data_u32, struct http_client *client,
//	struct handoff_out *out_ctx, int osd_arr_index, int thread_id);
//void handoff_out_send(struct handoff_out *out_ctx);
//void handoff_out_recv(struct handoff_out *out_ctx);
//
//int handoff_in_listen(int thread_id);
//void handoff_in_recv(struct handoff_in *in_ctx, bool *ready_to_send,
//        struct http_client **client_to_handoff_again);
//void handoff_in_send(struct handoff_in *in_ctx);
//
//void handoff_in_disconnect(struct handoff_in *in_ctx);
#include "socket_serialize.pb-c.h"
void handoff_in_deserialize(struct handoff_in *in_ctx, SocketSerialize *migration_info, ngx_log_t *log);
void handoff_out_serialize_rehandoff(struct http_client **client_to_handoff_again, SocketSerialize *migration_info, struct sockaddr_in *my_sockaddr, int to_migrate, int from_migrate);

#endif
