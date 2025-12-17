#ifndef __HANDOFF_H__
#define __HANDOFF_H__

#include "queue.h"
#include "forward.h"
#include "ebpf_forward.h"

#include "http_client.h"

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

#include "zlog.h"

extern zlog_category_t *zlog_handoff;
extern bool use_tc;
extern bool tc_offload;
extern bool tc_hybrid;
#define Q_SIZE 1000
extern rule_queue_t *q;

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
	rados_ioctx_t data_io_ctx;
	rados_ioctx_t bucket_io_ctx;
        struct http_client *client_to_handoff_again;
        bool wait_for_originaldone;
        struct http_client *client_for_originaldone;
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
        int osd_arr_index;
        int thread_id;
        struct handoff_out_queue *queue;
        // handoff out request currently sending out, deququed from queue
        struct http_client *client;
        uint8_t *recv_protobuf;
        uint32_t recv_protobuf_len;
        uint32_t recv_protobuf_received;
};

void handoff_out_serialize_reset(struct http_client *client);
void handoff_out_serialize(struct http_client *client);

void handoff_out_connect(struct handoff_out *out_ctx);
int handoff_out_reconnect(struct handoff_out *out_ctx);
void handoff_out_issue(int epoll_fd, uint32_t epoll_data_u32, struct http_client *client,
	struct handoff_out *out_ctx, int osd_arr_index, int thread_id);
void handoff_out_issue_urgent(int epoll_fd, uint32_t epoll_data_u32, struct http_client *client,
	struct handoff_out *out_ctx, int osd_arr_index, int thread_id);
void handoff_out_send(struct handoff_out *out_ctx);
void handoff_out_recv(struct handoff_out *out_ctx);

int handoff_in_listen(int thread_id);
void handoff_in_recv(struct handoff_in *in_ctx, bool *ready_to_send,
        struct http_client **client_to_handoff_again);
void handoff_in_send(struct handoff_in *in_ctx);

void handoff_in_disconnect(struct handoff_in *in_ctx);
//#include "proto/socket_serialize.pb-c.h"
//void handoff_in_deserialize(struct handoff_in *in_ctx, SocketSerialize *migration_info);

#endif
