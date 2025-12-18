#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>

#include <stdlib.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <errno.h>
#include <assert.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <linux/tls.h>
#include <netinet/tcp.h>

#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <inttypes.h>

#include "handoff.h"
#include "util.h"

//#include "object_store.h"
#include "http_client.h"
//#include "osd_mapping.h"
//#include "tls.h"

#include "socket_serialize.pb-c.h"

//#define USE_TC
//#define TC_OFFLOAD false

#define HYBRID_THRESHOLD 2097152

bool use_tc = false;
bool tc_offload = false;
bool tc_hybrid = false;

extern uint8_t my_mac[6];
extern struct sockaddr_in my_sockaddr;
//static const char *ifname = "enp23s0f0np0";

rule_queue_t *q;


//zlog_category_t *zlog_handoff;
//extern zlog_category_t *zlog_tls;


/*

          +--------+                 +--------+
          |SERVER A|                 |SERVER B|
          +--------+                 +--------+

      S3 Client HTTP GET
               |
               |
               v
    on_headers_complete_cb
               |
               |             +------------+
               v             |            v
     handoff_out_serialize   |     handoff_in_recv
               |             |            |
               |             |            |
               v             |            v
       handoff_out_issue     |  handoff_in_deserialize
               |             |            |
               |             |            |
               v             |            v
       handoff_out_send------+    handoff_in_send
                                          |
               +--------------------------+
               v
       handoff_out_recv
               |
               v
    handoff_out_apply_rule
               |
               v
     handoff_out_send_done
               |
               +--------------------------+
                                          v
                                  handoff_in_recv_done

*/

struct tcp_info_sub {
        uint8_t tcpi_state;
        uint8_t tcpi_ca_state;
        uint8_t tcpi_retransmits;
        uint8_t tcpi_probes;
        uint8_t tcpi_backoff;
        uint8_t tcpi_options;
        uint8_t tcpi_snd_wscale : 4;
        uint8_t tcpi_rcv_wscale : 4;
};

struct handoff_out_req {
    void* c;
    struct handoff_out_req* next;
};

//static struct handoff_out_req* handoff_out_req_create(void *client) {
//    struct handoff_out_req* new_req = (struct handoff_out_req*)malloc(sizeof(struct handoff_out_req));
//    if (!new_req) return NULL;
//
//	new_req->c = client;
//    new_req->next = NULL;
//
//    return new_req;
//}
//
//static struct handoff_out_queue* handoff_out_queue_create() {
//    struct handoff_out_queue* queue = (struct handoff_out_queue*)malloc(sizeof(struct handoff_out_queue));
//    if (!queue) return NULL;
//
//    queue->front = queue->rear = NULL;
//    queue->num_requests = 0;
//    return queue;
//}
//
//static int handoff_out_queue_is_empty(struct handoff_out_queue* queue) {
//    return queue->front == NULL;
//}
//
//// Function to add an element to the queue
//static void handoff_out_enqueue_front(struct handoff_out_queue* queue, void *client)
//{
//	struct handoff_out_req* new_req = handoff_out_req_create(client);
//	if (!new_req) {
//		zlog_error(zlog_handoff, "Heap Overflow");
//    		return;
//	}
//
//	queue->num_requests++;
//
//	// If queue is empty, then new node is front and rear both
//	if (queue->rear == NULL) {
//		queue->front = queue->rear = new_req;
//		return;
//	}
//
//	// Add the new node at the front of queue
//	new_req->next = queue->front;
//	queue->front = new_req;
//}
//
//// Function to add an element to the queue
//static void handoff_out_enqueue(struct handoff_out_queue* queue, void *client)
//{
//	struct handoff_out_req* new_req = handoff_out_req_create(client);
//	if (!new_req) {
//		zlog_error(zlog_handoff, "Heap Overflow");
//		return;
//	}
//
//	queue->num_requests++;
//
//	// If queue is empty, then new node is front and rear both
//	if (queue->rear == NULL) {
//		queue->front = queue->rear = new_req;
//		return;
//	}
//
//	// Add the new node at the end of queue and change rear
//	queue->rear->next = new_req;
//	queue->rear = new_req;
//}
//
//// caller have to check queue is empty before dequeue!!!
//static void handoff_out_dequeue(struct handoff_out_queue* queue, void **client) {
//	struct handoff_out_req* node = queue->front;
//	*client = node->c;
//
//	queue->front = queue->front->next;
//	// If front becomes NULL, then change rear also as NULL
//	if (queue->front == NULL) {
//		queue->rear = NULL;
//	}
//
//	free(node);
//	queue->num_requests--;
//}
//
// **special serialize for reset-handoff**
void handoff_out_serialize_reset(struct http_client *client, ngx_log_t *log)
{
	int ret;
	socklen_t slen;

	struct sockaddr_in self_sin;
	bzero(&self_sin, sizeof(self_sin));
	self_sin.sin_family = AF_INET;
	slen = sizeof(self_sin);
	ret = getsockname(client->fd, (struct sockaddr *)&self_sin, &slen);
	assert(ret == 0);

	// apply blocking
	ret = apply_redirection_ebpf(client->client_addr, self_sin.sin_addr.s_addr,
				client->client_port, self_sin.sin_port,
				client->client_addr, client->client_mac, self_sin.sin_addr.s_addr, my_mac,
				client->client_port, self_sin.sin_port, true);
	assert(ret == 0);
	//zlog_debug(zlog_handoff, "Applied blocking with eBPF (%d,%d) (fd=%d)", ntohs(client->client_port), ntohs(self_sin.sin_port), client->fd);
	//printf("handoff_out_serialize_reset(): Applied blocking with eBPF (%d,%d) (fd=%d)\n", ntohs(client->client_port), ntohs(self_sin.sin_port), client->fd);

	// build reset proto_buf
	SocketSerialize migration_info_reset = SOCKET_SERIALIZE__INIT;
	migration_info_reset.msg_type = HANDOFF_RESET_REQUEST;

	migration_info_reset.self_addr = self_sin.sin_addr.s_addr;
	migration_info_reset.self_port = self_sin.sin_port;
	migration_info_reset.peer_addr = client->client_addr;
	migration_info_reset.peer_port = client->client_port;

        ngx_log_debug5(NGX_LOG_DEBUG_EVENT, log, 0, "Serializing connection: client(%" PRIu64 ":%d) server(%" PRIu64 ":%d) (fd=%d)", migration_info_reset.peer_addr, ntohs(migration_info_reset.peer_port), migration_info_reset.self_addr, ntohs(migration_info_reset.self_port), client->fd);

	//zlog_debug(zlog_handoff, "Serializing connection: client(%" PRIu64 ":%d) server(%" PRIu64 ":%d) (fd=%d)",
	//	migration_info_reset.peer_addr, ntohs(migration_info_reset.peer_port),
	//	migration_info_reset.self_addr, ntohs(migration_info_reset.self_port), client->fd);

	int proto_len = socket_serialize__get_packed_size(&migration_info_reset);
	uint32_t net_proto_len = htonl(proto_len);
	client->proto_buf = malloc(sizeof(net_proto_len) + proto_len);
	socket_serialize__pack(&migration_info_reset, client->proto_buf + sizeof(net_proto_len));
	// add length of proto_buf at the begin
	memcpy(client->proto_buf, &net_proto_len, sizeof(net_proto_len));
	client->proto_buf_sent = 0;
	client->proto_buf_len = sizeof(net_proto_len) + proto_len;

	client->to_migrate = client->from_migrate;

	close(client->fd);
	client->fd = -client->fd;
}

// **special serialize for re-handoff**
void handoff_out_serialize_rehandoff(struct http_client **client_to_handoff_again, SocketSerialize *migration_info, struct sockaddr_in *my_sockaddr, int to_migrate, int from_migrate)
{
	int ret = 0;

	// apply blocking
	ret = apply_redirection_ebpf(migration_info->peer_addr, my_sockaddr->sin_addr.s_addr,
			migration_info->peer_port, htons(ntohs(migration_info->self_port) - 1 - 1),
			migration_info->peer_addr, (uint8_t *)&migration_info->peer_mac, my_sockaddr->sin_addr.s_addr, my_mac,
			migration_info->peer_port, migration_info->self_port, true);
	assert(ret == 0);
	//printf("Rehandoff: Applied blocking with eBPF (%d,%d) (fd=%d)\n", ntohs(migration_info->peer_port), ntohs(migration_info->self_port) - 1 - 1, 0);

	// we set fd as 0 so it will not considered as reset handoff
	struct http_client *client = create_http_client(-1, 0);
	client->from_migrate = from_migrate;
	client->to_migrate = to_migrate;
	client->acting_primary_osd_id = client->to_migrate;
	client->client_addr = migration_info->peer_addr;
	client->client_port = migration_info->peer_port;

	SocketSerialize migration_info_handoff_again = *migration_info;

	migration_info_handoff_again.msg_type = HANDOFF_REQUEST;
	migration_info_handoff_again.self_addr = my_sockaddr->sin_addr.s_addr;

	int proto_len = socket_serialize__get_packed_size(&migration_info_handoff_again);
	uint32_t net_proto_len = htonl(proto_len);
	client->proto_buf = malloc(sizeof(net_proto_len) + proto_len);
	socket_serialize__pack(&migration_info_handoff_again, client->proto_buf + sizeof(net_proto_len));
	// add length of proto_buf at the begin
	memcpy(client->proto_buf, &net_proto_len, sizeof(net_proto_len));
	client->proto_buf_sent = 0;
	client->proto_buf_len = sizeof(net_proto_len) + proto_len;

	*client_to_handoff_again = client;
}

void handoff_out_serialize(struct http_client *client, ngx_log_t *log)
{
	int ret = -1;
	int fd = client->fd;
	//int epfd = client->epoll_fd;
	struct tcp_info_sub info;

	socklen_t slen;
	struct sockaddr_in self_sin;
	bzero(&self_sin, sizeof(self_sin));
	self_sin.sin_family = AF_INET;
	slen = sizeof(self_sin);
	ret = getsockname(fd, (struct sockaddr *)&self_sin, &slen);
	assert(ret == 0);

	// apply blocking
	ret = apply_redirection_ebpf(client->client_addr, self_sin.sin_addr.s_addr,
				client->client_port, self_sin.sin_port,
				client->client_addr, client->client_mac, self_sin.sin_addr.s_addr, my_mac,
				client->client_port, self_sin.sin_port, true);
	assert(ret == 0);
	//printf("handoff_out_serialize(): Applied blocking with eBPF (%d,%d) (fd=%d)\n", ntohs(client->client_port), ntohs(self_sin.sin_port), client->fd);
	ngx_log_debug3(NGX_LOG_DEBUG_EVENT, log, 0, "handoff_out_serialize(): Applied blocking with eBPF (%d,%d) (fd=%d)", ntohs(client->client_port), ntohs(self_sin.sin_port), client->fd);
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, log, 0, "ngx_event_connect_serialized before");

// check if established
	slen = sizeof(info);
	ret = getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &slen);
	assert(ret == 0);
//ret = info.tcpi_state == TCP_ESTABLISHED;
	if (info.tcpi_state == TCP_ESTABLISHED) {
		ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0, "fd=%d TCP SOCKET STATE ESTABLISHED", fd);
	}
	else {
		ngx_log_debug2(NGX_LOG_DEBUG_EVENT, log, 0, "fd=%d TCP SOCKET STATE %d", fd, info.tcpi_state);
	}

	//assert(ret == 0);

	ret = setsockopt(fd, IPPROTO_TCP, TCP_REPAIR, &(int){1}, sizeof(int));
if (ret != 0) {
	ngx_log_debug3(NGX_LOG_DEBUG_EVENT, log, 0, "setsockopt(fd, IPPROTO_TCP, TCP_REPAIR, &(int){1}, sizeof(int)) = %d : %s (%d)", ret, strerror(ngx_errno), ngx_errno);
exit(1);
}
//	assert(ret == 0);

	int sendq_len, unsentq_len, recvq_len;
	ret = ioctl(fd, SIOCOUTQ, &sendq_len);
	assert(ret == 0);
	ret = ioctl(fd, SIOCOUTQNSD, &unsentq_len);
	assert(ret == 0);
	ret = ioctl(fd, SIOCINQ, &recvq_len);
	assert(ret == 0);

	uint32_t mss, ts;
	socklen_t olen_mss = sizeof(mss);
	socklen_t olen_ts = sizeof(ts);
	ret = getsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &mss, &olen_mss);
	assert(ret == 0);
	ret = getsockopt(fd, IPPROTO_TCP, TCP_TIMESTAMP, &ts, &olen_ts);
	assert(ret == 0);

	struct tcp_repair_window window;
	slen = sizeof(window);
	ret = getsockopt(fd, IPPROTO_TCP, TCP_REPAIR_WINDOW, &window, &slen);
	assert(ret == 0);

	const int qid_snd = TCP_SEND_QUEUE;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_REPAIR_QUEUE, &qid_snd, sizeof(qid_snd));
	assert(ret == 0);
	socklen_t seqno_send;
	slen = sizeof(seqno_send);
	ret = getsockopt(fd, IPPROTO_TCP, TCP_QUEUE_SEQ, &seqno_send, &slen);
	assert(ret == 0);
	const int peek = MSG_PEEK | MSG_DONTWAIT;
	uint8_t *sndbuf = NULL;
	if (sendq_len)
	{
		sndbuf = calloc(1, sendq_len + 1);
		assert(sndbuf != NULL);
		ret = recv(fd, sndbuf, sendq_len + 1, peek);
		assert(ret == sendq_len);
	}

	const int qid_rcv = TCP_RECV_QUEUE;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_REPAIR_QUEUE, &qid_rcv, sizeof(qid_rcv));
	assert(ret == 0);
	socklen_t seqno_recv;
	slen = sizeof(seqno_recv);
	ret = getsockopt(fd, IPPROTO_TCP, TCP_QUEUE_SEQ, &seqno_recv, &slen);
	assert(ret == 0);
	uint8_t *rcvbuf = NULL;
	if (recvq_len) {
		rcvbuf = calloc(1, recvq_len + 1);
		assert(rcvbuf != NULL);
		ret = recv(fd, rcvbuf, recvq_len + 1, peek);
		assert(ret == recvq_len);
	}

	int ktlsbuf_len = 0;
	uint8_t *ktlsbuf_data = NULL;

	if (client->tls.is_ktls_set) {
		ktlsbuf_len = 2 * sizeof(struct tls12_crypto_info_aes_gcm_256);
		ktlsbuf_data = malloc(ktlsbuf_len);

		struct tls12_crypto_info_aes_gcm_256 *crypto_info_send = (struct tls12_crypto_info_aes_gcm_256*)ktlsbuf_data;
		struct tls12_crypto_info_aes_gcm_256 *crypto_info_recv = (struct tls12_crypto_info_aes_gcm_256*)ktlsbuf_data +
			sizeof(struct tls12_crypto_info_aes_gcm_256);

		socklen_t optlen = sizeof(struct tls12_crypto_info_aes_gcm_256);
		if (getsockopt(fd, SOL_TLS, TLS_TX, crypto_info_send, &optlen)) {
			//zlog_fatal(zlog_tls, "Couldn't get TLS_TX option (%s) (fd=%d)", strerror(errno), client->fd);
			exit(EXIT_FAILURE);
		}

		optlen = sizeof(struct tls12_crypto_info_aes_gcm_256);
		if (getsockopt(fd, SOL_TLS, TLS_RX, crypto_info_recv, &optlen)) {
			//zlog_fatal(zlog_tls, "Couldn't get TLS_RX option (%s) (fd=%d)", strerror(errno), client->fd);
			exit(EXIT_FAILURE);
		}
	}

//	/* clean up */
//	ret = epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
//	assert(ret == 0);
	close(fd);

	/* pack & send handoff msg */
	SocketSerialize migration_info = SOCKET_SERIALIZE__INIT;
	migration_info.msg_type = HANDOFF_REQUEST;
	if (client->from_migrate != -1) {
		migration_info.msg_type = HANDOFF_BACK_REQUEST;
		ngx_log_debug0(NGX_LOG_DEBUG_EVENT, log, 0, "Seriailize HANDOFF_BACK_REQUEST");
	}

	//tcp variables setting up
	migration_info.sendq_len = sendq_len;
	migration_info.unsentq_len = unsentq_len;
	migration_info.recvq_len = recvq_len;
	migration_info.mss = mss;
	migration_info.timestamp = ts;
	migration_info.send_wscale = info.tcpi_snd_wscale;
	migration_info.recv_wscale = info.tcpi_rcv_wscale;
	migration_info.snd_wl1 = window.snd_wl1;
	migration_info.snd_wnd = window.snd_wnd;
	migration_info.max_window = window.max_window;
	migration_info.rev_wnd = window.rcv_wnd;
	migration_info.rev_wup = window.rcv_wup;
	migration_info.self_addr = self_sin.sin_addr.s_addr;
	if (client->from_migrate != -1) {
		migration_info.self_port = self_sin.sin_port;
		//zlog_debug(zlog_handoff, "I am fake server, this is a hand off back request, do not increment self port: %d", ntohs(migration_info.self_port ));
	}
	else {
//		migration_info.self_port = htons(ntohs(self_sin.sin_port) + get_my_osd_id() + 1);
		migration_info.self_port = htons(ntohs(self_sin.sin_port) + 1 + 1);
	}
	migration_info.peer_addr = client->client_addr;
	memcpy(&(migration_info.peer_mac), client->client_mac, sizeof(uint8_t) * 6);
	migration_info.peer_port = client->client_port;
	migration_info.seq = seqno_send;
	migration_info.ack = seqno_recv;
	migration_info.sendq.len = sendq_len;
	migration_info.sendq.data = sndbuf;
	migration_info.recvq.len = recvq_len;
	migration_info.recvq.data = rcvbuf;
	migration_info.ktlsbuf.len = ktlsbuf_len;
	migration_info.ktlsbuf.data = ktlsbuf_data;

	// serialize http client
	//migration_info.method = client->method;

	migration_info.bucket_name = malloc(sizeof(char) * (strlen(client->bucket_name) + 1));
	snprintf(migration_info.bucket_name, strlen(client->bucket_name) + 1, "%s", client->bucket_name);

	migration_info.object_name = malloc(sizeof(char) * (strlen(client->object_name) + 1));
	snprintf(migration_info.object_name, strlen(client->object_name) + 1, "%s", client->object_name);

	migration_info.uri_str = malloc(sizeof(char) * (strlen(client->uri_str) + 1));
	snprintf(migration_info.uri_str, strlen(client->uri_str) + 1, "%s", client->uri_str);

	migration_info.object_size = client->object_size;

	migration_info.acting_primary_osd_id = client->acting_primary_osd_id;

	size_t proto_len = socket_serialize__get_packed_size(&migration_info);
	uint32_t net_proto_len = htonl(proto_len);
	uint8_t *proto_buf = malloc(sizeof(net_proto_len) + proto_len);
	socket_serialize__pack(&migration_info, proto_buf + sizeof(net_proto_len));
	// add length of proto_buf at the begin
	memcpy(proto_buf, &net_proto_len, sizeof(net_proto_len));

	client->proto_buf = proto_buf;
	client->proto_buf_sent = 0;
	client->proto_buf_len = sizeof(net_proto_len) + proto_len;

	free(migration_info.uri_str);
	free(migration_info.object_name);
	free(migration_info.bucket_name);

	if (ktlsbuf_data != NULL) {
		free(ktlsbuf_data);
	}
//zlog_info(zlog_handoff, "Socket serialized");
}

static void set_socket_non_blocking(int socket_fd)
{
	int flags = fcntl(socket_fd, F_GETFL, 0);
	if (flags == -1) {
		perror("fcntl");
		exit(EXIT_FAILURE);
	}

	flags |= O_NONBLOCK;
	if (fcntl(socket_fd, F_SETFL, flags) == -1) {
		perror("fcntl");
		exit(EXIT_FAILURE);
	}
}
//
//void handoff_out_connect(struct handoff_out *out_ctx) {
//	//zlog_debug(zlog_handoff, "HANDOFF_OUT To connect to OSD %d (%s:%d)",
//		osd_ids[out_ctx->osd_arr_index],
//		osd_addr_strs[out_ctx->osd_arr_index],
//		HANDOFF_CTRL_PORT + out_ctx->thread_id);
//
//	out_ctx->fd = socket(AF_INET, SOCK_STREAM, 0);
//	if (out_ctx->fd == -1) {
//		//zlog_fatal(zlog_handoff, "create socket fail: %s", strerror(errno));
//		exit(EXIT_FAILURE);
//	}
//
//	if (setsockopt(out_ctx->fd, IPPROTO_TCP, TCP_QUICKACK, &(int){1}, sizeof(int)) == -1) {
//		//zlog_fatal(zlog_handoff, "setsockopt TCP_QUICKACK fail: %s", strerror(errno));
//		exit(EXIT_FAILURE);
//	}
//
//	if (setsockopt(out_ctx->fd, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) == -1) {
//		//zlog_fatal(zlog_handoff, "setsockopt TCP_NODELAY fail: %s", strerror(errno));
//		exit(EXIT_FAILURE);
//	}
//
//	set_socket_non_blocking(out_ctx->fd);
//
//	struct sockaddr_in out_addr = osd_addrs[out_ctx->osd_arr_index];
//	out_addr.sin_port = htons(HANDOFF_CTRL_PORT + out_ctx->thread_id);
//	if (connect(out_ctx->fd, (struct sockaddr*)&out_addr, sizeof(out_addr)) == -1) {
//		if (errno != EINPROGRESS) {
//			//zlog_fatal(zlog_handoff, "Failed to connect to OSD %d (out_ctx->fd=%d): %s", osd_ids[out_ctx->osd_arr_index], out_ctx->fd, strerror(errno));
//			close(out_ctx->fd);
//			exit(EXIT_FAILURE);
//		}
//		out_ctx->is_fd_connected = false;
//		return;
//	}
//
//	out_ctx->is_fd_connected = true;
//	out_ctx->reconnect_count = 0;
//
//	return;
//}
//
//int handoff_out_reconnect(struct handoff_out *out_ctx) {
//	struct epoll_event event = {0};
//
//	if (out_ctx->is_fd_connected == false) {
//		int val = 0;
//		socklen_t len = sizeof(val);
//		int ret = getsockopt(out_ctx->fd, SOL_SOCKET, SO_ERROR, &val, &len);
//		if (ret != 0) {
//			//zlog_fatal(zlog_handoff, "error getting socket error code: %s", strerror(errno));
//			exit(EXIT_FAILURE);
//		}
//
//		if (val != 0) {
//			zlog_error(zlog_handoff, "socket error: %s", strerror(val));
//		} else {
//			out_ctx->is_fd_connected = true;
//			out_ctx->reconnect_count = 0;
//			goto connected;
//		}
//	}
//
//	out_ctx->reconnect_count++;
//	out_ctx->is_fd_connected = false;
//	if (out_ctx->reconnect_count > MAX_HANDOFF_OUT_RECONNECT) {
//		//zlog_fatal(zlog_handoff, "HANDOFF_OUT try RE-connect to OSD %d too many times (%s:%d), reconnect count %d",
//				osd_ids[out_ctx->osd_arr_index],
//				osd_addr_strs[out_ctx->osd_arr_index],
//				HANDOFF_CTRL_PORT + out_ctx->thread_id,
//			out_ctx->reconnect_count);
//		exit(EXIT_FAILURE);
//	}
//
//	zlog_error(zlog_handoff, "HANDOFF_OUT Try RE-connect to OSD %d (%s:%d), reconnect count %d",
//			osd_ids[out_ctx->osd_arr_index],
//			osd_addr_strs[out_ctx->osd_arr_index],
//			HANDOFF_CTRL_PORT + out_ctx->thread_id,
//			out_ctx->reconnect_count);
//
//	if (out_ctx->fd != 0) close(out_ctx->fd);
//	handoff_out_connect(out_ctx);
//
//	event.data.ptr = out_ctx;
//	event.events = EPOLLOUT;
//	if (epoll_ctl(out_ctx->epoll_fd, EPOLL_CTL_ADD, out_ctx->fd, &event) == -1) {
//		//zlog_fatal(zlog_handoff, "HANDOFF_OUT Failed to add control conn to epoll (fd=%d,osd=%d): %s", out_ctx->fd, osd_ids[out_ctx->osd_arr_index], strerror(errno));
//		close(out_ctx->fd);
//		exit(EXIT_FAILURE);
//	}
//
//	if (out_ctx->is_fd_connected) {
//		goto connected;
//	}
//
//	return -1;
//
//connected:
//
//	bool send = false;
//
//	if (out_ctx->client == NULL) {
//		send = true;
//	} else {
//		if (out_ctx->client->proto_buf != NULL) {
//			send = true;
//		}
//	}
//
//	if (send) {
//		handoff_out_send(out_ctx);
//	} else {
//		event.data.ptr = out_ctx;
//		event.events = EPOLLIN;
//		if (epoll_ctl(out_ctx->epoll_fd, EPOLL_CTL_MOD, out_ctx->fd, &event) == -1) {
//			perror("epoll_ctl");
//			close(out_ctx->fd);
//			exit(EXIT_FAILURE);
//		}
//		handoff_out_recv(out_ctx);
//	}
//
//	return 0;
//}
//
//// have to serialize before issue
//static void do_handoff_out_issue(int epoll_fd, uint32_t epoll_data_u32, struct http_client *client,
//	struct handoff_out *out_ctx, int osd_arr_index, int thread_id, bool urgent)
//{
//	// enqueue this handoff request
//	if (!out_ctx->queue) {
//		out_ctx->queue = handoff_out_queue_create();
//	}
//
//	if (urgent) {
//		handoff_out_enqueue_front(out_ctx->queue, client);
//		//zlog_debug(zlog_handoff, "HANDOFF_OUT (front)enqueued (backlog=%d) Migration (OSD=%d,fd=%d,port=%d)",
//			out_ctx->queue->num_requests, osd_ids[out_ctx->osd_arr_index], client->fd, ntohs(client->client_port));
//	} else {
//		handoff_out_enqueue(out_ctx->queue, client);
//		//zlog_debug(zlog_handoff, "HANDOFF_OUT enqueued (backlog=%d) Migration (OSD=%d,fd=%d,port=%d)",
//			out_ctx->queue->num_requests, osd_ids[out_ctx->osd_arr_index], client->fd, ntohs(client->client_port));
//	}
//
//	if (out_ctx->client) {
//		return;
//	}
//
//	// we have a connected fd and it is in epoll, let the epoll to consume this new request
//	if (out_ctx->is_fd_in_epoll) {
//		return;
//	}
//
//	// we don't have a connceted fd, we need to create one
//	if (out_ctx->fd == 0) {
//		handoff_out_connect(out_ctx);
//	}
//
//	// we added this ctx into epoll
//	struct epoll_event event = {0};
//	out_ctx->epoll_data_u32 = epoll_data_u32;
//	event.data.ptr = out_ctx;
//	event.events = EPOLLOUT;
//	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, out_ctx->fd, &event) == -1) {
//		//zlog_fatal(zlog_handoff, "HANDOFF_OUT Failed to add control conn to epoll (out_ctx->fd=%d,fd=%d,osd=%d,port=%d): %s", out_ctx->fd, client->fd, osd_ids[out_ctx->osd_arr_index], ntohs(client->client_port), strerror(errno));
//		close(out_ctx->fd);
//		exit(EXIT_FAILURE);
//	}
//
//	out_ctx->is_fd_in_epoll = true;
//	out_ctx->epoll_fd = epoll_fd;
//
//	if (out_ctx->is_fd_connected) {
//		handoff_out_send(out_ctx);
//	}
//}
//
//void handoff_out_issue(int epoll_fd, uint32_t epoll_data_u32, struct http_client *client,
//	struct handoff_out *out_ctx, int osd_arr_index, int thread_id)
//{
//	return do_handoff_out_issue(epoll_fd, epoll_data_u32, client, out_ctx, osd_arr_index, thread_id, false);
//}
//
//void handoff_out_issue_urgent(int epoll_fd, uint32_t epoll_data_u32, struct http_client *client,
//	struct handoff_out *out_ctx, int osd_arr_index, int thread_id)
//{
//	return do_handoff_out_issue(epoll_fd, epoll_data_u32, client, out_ctx, osd_arr_index, thread_id, true);
//}
//
//// 0. if we dont have a outstaing client, try dequeue from queue,
////    if queue empty, then delete this fd from epoll
//// 1. if we have a outstading client, send until whole thing sent out (via epoll)
//// 1.a if sent failed with -1, delete current fd then re-connect
//// 2. if we have sent out the whole thing, we change to in mode and wait for response
//void handoff_out_send(struct handoff_out *out_ctx)
//{
//	if (out_ctx->client == NULL) {
//		if (out_ctx->queue == NULL) {
//			//zlog_fatal(zlog_handoff, "out_ctx->queue shouldn't be NULL here");
//			exit(EXIT_FAILURE);
//		}
//		if (handoff_out_queue_is_empty(out_ctx->queue)) {
//			return;
//		}
//		handoff_out_dequeue(out_ctx->queue, (void **)&out_ctx->client);
//	}
//
//	//zlog_debug(zlog_handoff, "HANDOFF_OUT dequeued (backlog %d) Migration work (OSD=%d,out_ctx->fd=%d,fd=%d)",
//		out_ctx->queue->num_requests, out_ctx->client->to_migrate, out_ctx->fd, out_ctx->client->fd);
//
//	int ret = send(out_ctx->fd, out_ctx->client->proto_buf + out_ctx->client->proto_buf_sent,
//		out_ctx->client->proto_buf_len - out_ctx->client->proto_buf_sent, 0);
//	if ((ret == 0) || (ret == -1 && errno != EAGAIN)) {
//		zlog_error(zlog_handoff, "handoff_out_send send error (%d): %s", errno, strerror(errno));
//		handoff_out_reconnect(out_ctx);
//		return;
//	}
//	if (ret == -1 && errno == EAGAIN) {
//		return;
//	}
//
//	out_ctx->client->proto_buf_sent += ret;
//
//	// send done
//	if (out_ctx->client->proto_buf_len == out_ctx->client->proto_buf_sent) {
//		//zlog_debug(zlog_handoff, "HANDOFF_OUT migration request sent (OSD=%d,fd=%d,port=%d)", out_ctx->client->to_migrate, out_ctx->client->fd, ntohs(out_ctx->client->client_port));
//
//		if (out_ctx->client->proto_buf != NULL) {
//			free(out_ctx->client->proto_buf);
//			out_ctx->client->proto_buf = NULL;
//		}
//		out_ctx->client->proto_buf_len = 0;
//		out_ctx->client->proto_buf_sent = 0;
//		struct epoll_event event = {0};
//		event.data.ptr = out_ctx;
//		event.events = EPOLLIN;
//		if (epoll_ctl(out_ctx->epoll_fd, EPOLL_CTL_MOD, out_ctx->fd, &event) == -1) {
//			//zlog_fatal(zlog_handoff, "Change control socket to receive failed (out_ctx->fd=%d,fd=%d): %s", out_ctx->fd, out_ctx->client->fd, strerror(errno));
//			close(out_ctx->fd);
//			exit(EXIT_FAILURE);
//		}
//	}
//}
//
//static void handoff_out_send_done(struct handoff_out *out_ctx)
//{
//	//zlog_debug(zlog_handoff, "HANDOFF_OUT send done (osd=%d,out_ctx->fd=%d,fd=%d,port=%d)", osd_ids[out_ctx->osd_arr_index], out_ctx->fd, out_ctx->client->fd, ntohs(out_ctx->client->client_port));
//
//	uint32_t magic_number = UINT32_MAX;
//	int ret = send(out_ctx->fd, &magic_number,
//		sizeof(magic_number), 0);
//	if (ret != sizeof(magic_number)) {
//		//zlog_fatal(zlog_handoff, "Fail to send handoff_out magic number %" PRIu32 ": ret=%d", magic_number, ret);
//		exit(EXIT_FAILURE);
//	}
//}
//
////static int hex2num(char c)
////{
////        if (c >= '0' && c <= '9')
////                return c - '0';
////        if (c >= 'a' && c <= 'f')
////                return c - 'a' + 10;
////        if (c >= 'A' && c <= 'F')
////                return c - 'A' + 10;
////        return -1;
////}
////
////static int hwaddr_aton(const char *txt, __u8 *addr)
////{
////        int i;
////
////        for (i = 0; i < 6; i++) {
////        int a, b;
////
////        a = hex2num(*txt++);
////        if (a < 0)
////                return -1;
////        b = hex2num(*txt++);
////        if (b < 0)
////                return -1;
////        *addr++ = (a << 4) | b;
////        if (i < 5 && *txt++ != ':')
////                return -1;
////        }
////
////        return 0;
////}
//
//void handoff_out_recv(struct handoff_out *out_ctx)
//{
//	if (out_ctx->recv_protobuf == NULL) {
//		int ret = recv(out_ctx->fd, &out_ctx->recv_protobuf_len, sizeof(out_ctx->recv_protobuf_len), 0);
//		if ((ret == 0) || (ret == -1 && errno != EAGAIN)) {
//			perror("handoff_out_recv recv1");
//			handoff_out_reconnect(out_ctx);
//			return;
//		}
//		if (ret == -1 && errno == EAGAIN) {
//			return;
//		}
//		if (ret != sizeof(out_ctx->recv_protobuf_len)) {
//			//zlog_fatal(zlog_handoff, "TCP recv not equal to 4 bytes on header");
//			exit(EXIT_FAILURE);
//		}
//		out_ctx->recv_protobuf_len = ntohl(out_ctx->recv_protobuf_len);
//		if (out_ctx->recv_protobuf_len == 0) {
//			//zlog_fatal(zlog_handoff, "out_ctx->recv_protobuf_len is zero");
//			exit(EXIT_FAILURE);
//		}
//		out_ctx->recv_protobuf = malloc(out_ctx->recv_protobuf_len);
//	}
//
//	int ret = recv(out_ctx->fd, out_ctx->recv_protobuf + out_ctx->recv_protobuf_received,
//		out_ctx->recv_protobuf_len - out_ctx->recv_protobuf_received, 0);
//	if ((ret == 0) || (ret == -1 && errno != EAGAIN)) {
//		zlog_error(zlog_handoff, "fail to receive protobuf, reconnect: %s", strerror(errno));
//		handoff_out_reconnect(out_ctx);
//		return;
//	}
//	if (ret == -1 && errno == EAGAIN) {
//		return;
//	}
//
//	out_ctx->recv_protobuf_received += ret;
//	if (out_ctx->recv_protobuf_received < out_ctx->recv_protobuf_len)
//		return;
//
//	SocketSerialize *migration_info = socket_serialize__unpack(NULL,
//		out_ctx->recv_protobuf_len, out_ctx->recv_protobuf);
//	if (migration_info == NULL) {
//		//zlog_fatal(zlog_handoff, "unable to unpack recv protobuf");
//		exit(EXIT_FAILURE);
//	}
//	if (migration_info->msg_type != HANDOFF_DONE) {
//		//zlog_fatal(zlog_handoff, "HANDOFF_OUT Received migration response not HANDOFF_DONE");
//		exit(EXIT_FAILURE);
//	}
//
//	//zlog_debug(zlog_handoff, "HANDOFF_OUT Received response for migration request (osd=%d,psize=%ld,out_ctx->fd=%d,fd=%d,port=%d)", out_ctx->client->to_migrate, migration_info->object_size, out_ctx->fd, out_ctx->client->fd, ntohs(out_ctx->client->client_port));
//
//	free(out_ctx->recv_protobuf);
//	out_ctx->recv_protobuf = NULL;
//	out_ctx->recv_protobuf_len = 0;
//	out_ctx->recv_protobuf_received = 0;
//
//	uint8_t fake_server_mac[6];
//	memcpy(fake_server_mac, &(migration_info->peer_mac), sizeof(uint8_t) * 6);
//
//	if (out_ctx->client->from_migrate == -1) {
//		// normal handoff
//		// insert redirection rule: peer mac is fake server mac
//		if (use_tc && !tc_hybrid) {
//			// case 1: only TC(-sw/hw)
//			ret = apply_redirection(migration_info->peer_addr, migration_info->self_addr,
//						migration_info->peer_port, htons(ntohs(migration_info->self_port) - get_my_osd_id() - 1),
//						migration_info->peer_addr, my_mac, osd_addrs[out_ctx->osd_arr_index].sin_addr.s_addr, fake_server_mac,
//						migration_info->peer_port, migration_info->self_port, false, tc_offload); //TC_OFFLOAD);
//			assert(ret == 0);
//		}
//		else {
//			ret = apply_redirection_ebpf(migration_info->peer_addr, migration_info->self_addr,
//						migration_info->peer_port, htons(ntohs(migration_info->self_port) - get_my_osd_id() - 1),
//						migration_info->peer_addr, my_mac, osd_addrs[out_ctx->osd_arr_index].sin_addr.s_addr, fake_server_mac,
//						migration_info->peer_port, migration_info->self_port, false);
//			assert(ret == 0);
//
//			if (tc_hybrid) {
//				rule_args_t args;
//				args.skip = false;
//				args.in_progress = false;
//				args.src_ip = migration_info->peer_addr;
//				args.dst_ip = migration_info->self_addr;
//				args.src_port = migration_info->peer_port;
//				args.dst_port = htons(ntohs(migration_info->self_port) - get_my_osd_id() - 1);
//				args.new_src_ip = migration_info->peer_addr;
//				memcpy(args.new_src_mac, my_mac, sizeof(uint8_t) * 6);
//				args.new_dst_ip = osd_addrs[out_ctx->osd_arr_index].sin_addr.s_addr;
//				memcpy(args.new_dst_mac, fake_server_mac, sizeof(uint8_t) * 6);
//				args.new_src_port = migration_info->peer_port;
//				args.new_dst_port = migration_info->self_port;
//				args.block = false;
//				args.hw_offload = tc_offload;
//
//				if ((migration_info->object_size < HYBRID_THRESHOLD) || !rule_enqueue(q, &args)) {
//					/* queue is full, insert dummy rule and give up hw rule */
//					ret = apply_redirection_dummy(migration_info->peer_addr, migration_info->self_addr,
//								migration_info->peer_port, htons(ntohs(migration_info->self_port) - get_my_osd_id() - 1),
//								migration_info->peer_addr, my_mac, osd_addrs[out_ctx->osd_arr_index].sin_addr.s_addr, fake_server_mac,
//								migration_info->peer_port, migration_info->self_port);
//					assert(ret == 0);
//					//zlog_debug(zlog_handoff, "Queue full or object too small (size=%ld), insert dummy rule instead (osd=%d,out_ctx->fd=%d,fd=%d) client(%" PRIu64 ":%d) server(%" PRIu64 ":%d) to fake server(%u:%d)",
//						migration_info->object_size, out_ctx->client->to_migrate, out_ctx->fd, out_ctx->client->fd,
//						migration_info->peer_addr, ntohs(migration_info->peer_port),
//						migration_info->self_addr, htons(ntohs(migration_info->self_port) - get_my_osd_id() - 1),
//						osd_addrs[out_ctx->osd_arr_index].sin_addr.s_addr, ntohs(migration_info->self_port));
//				}
//			}
//		}
//		//zlog_debug(zlog_handoff, "HANDOFF_OUT Apply redirection rule (osd=%d,size=%ld,out_ctx->fd=%d,fd=%d) client(%" PRIu64 ":%d) server(%" PRIu64 ":%d) to fake server(%u:%d)",
//				out_ctx->client->to_migrate, migration_info->object_size, out_ctx->fd, out_ctx->client->fd,
//				migration_info->peer_addr, ntohs(migration_info->peer_port),
//				migration_info->self_addr, htons(ntohs(migration_info->self_port) - get_my_osd_id() - 1),
//				osd_addrs[out_ctx->osd_arr_index].sin_addr.s_addr, ntohs(migration_info->self_port));
//
//		// we need to remove redirection if only TC is used.
//		// redirection should not be removed when eBPF is used as blocking will be updated to forwarding
//		//#ifdef USE_TC
//		if (use_tc && !tc_hybrid) {
//			// remove blocking
//			//zlog_debug(zlog_handoff, "HANDOFF_OUT To remove blocking rule after apply redirection (osd=%d,client=%" PRIu64 ":%d,original_server=%" PRIu64 ":%d,out_ctx->fd=%d,fd=%d)",
//				out_ctx->client->to_migrate,
//				migration_info->peer_addr, ntohs(migration_info->peer_port),
//				migration_info->self_addr, ntohs(migration_info->self_port) - get_my_osd_id() - 1,
//				out_ctx->fd, out_ctx->client->fd);
//			ret = remove_redirection_ebpf(migration_info->peer_addr, migration_info->self_addr,
//						migration_info->peer_port, htons(ntohs(migration_info->self_port) - get_my_osd_id() - 1));
//			assert(ret == 0);
//		}
//	} else {
//		// handoff back and handoff reset
//		// remove src IP modification
//		//zlog_debug(zlog_handoff, "HANDOFF_OUT Handing connection back to original server or conn reset (osd=%d,conn=%d,port=%d)",
//					out_ctx->client->to_migrate, out_ctx->client->fd, ntohs(out_ctx->client->client_port));
//		//if (use_tc) {
//		//	ret = remove_redirection(migration_info->self_addr, migration_info->peer_addr,
//		//				migration_info->self_port, migration_info->peer_port);
//		//} else {
//			ret = remove_redirection_ebpf(migration_info->self_addr, migration_info->peer_addr,
//						migration_info->self_port, migration_info->peer_port);
//		//}
//		assert(ret == 0);
//		//zlog_debug(zlog_handoff, "Removed src ip modification client(%" PRIu64 ":%d) self(%" PRIu64 ":%d)",
//					migration_info->peer_addr, ntohs(migration_info->peer_port),
//					migration_info->self_addr, ntohs(migration_info->self_port));
//
//		//zlog_debug(zlog_handoff, "HANDOFF_OUT To remove blocking rule after removing src IP modification rule (osd=%d,client=%" PRIu64 ":%d,original_server=%" PRIu64 ":%d,out_ctx->fd=%d,fd=%d)",
//			out_ctx->client->to_migrate,
//			migration_info->peer_addr, ntohs(migration_info->peer_port),
//			migration_info->self_addr, ntohs(migration_info->self_port),
//			out_ctx->fd, out_ctx->client->fd);
//		ret = remove_redirection_ebpf(migration_info->peer_addr, migration_info->self_addr,
//					migration_info->peer_port, migration_info->self_port);
//		assert(ret == 0);
//	}
//
//	// we don't need this for handoff_reset where fd already closed
//	// if (out_ctx->client->fd >= 0) {
//	// remove blocking
//	// }
//
//	handoff_out_send_done(out_ctx);
//
//	tls_free_client(out_ctx->client);
//	free_http_client(out_ctx->client);
//	out_ctx->client = NULL;
//	socket_serialize__free_unpacked(migration_info, NULL);
//
//	if (handoff_out_queue_is_empty(out_ctx->queue)) {
//		if (epoll_ctl(out_ctx->epoll_fd, EPOLL_CTL_DEL, out_ctx->fd, NULL) == -1) {
//			//zlog_fatal(zlog_handoff, "Failed to remove control connection from epoll (out_ctx->fd=%d,fd=%d): %s", out_ctx->fd, out_ctx->client->fd, strerror(errno));
//			exit(EXIT_FAILURE);
//		}
//		//zlog_debug(zlog_handoff, "Set is_fd_in_epoll to false");
//		out_ctx->is_fd_in_epoll = false;
//		return;
//	} else {
//		struct epoll_event event = {0};
//		event.data.ptr = out_ctx;
//		event.events = EPOLLOUT;
//		if (epoll_ctl(out_ctx->epoll_fd, EPOLL_CTL_MOD, out_ctx->fd, &event) == -1) {
//			//zlog_fatal(zlog_handoff, "Failed to set control socket to send mode (out_ctx->fd=%d,fd=%d): %s", out_ctx->fd, out_ctx->client->fd, strerror(errno));
//			close(out_ctx->fd);
//			exit(EXIT_FAILURE);
//		}
//		handoff_out_send(out_ctx);
//	}
//}
//
static int set_queue_seq(int fd, int queue, uint32_t seq)
{
	//zlog_debug(zlog_handoff, "setting %d queue seq to %u (rfd=%d)",
	//	queue, seq, fd);

	if (setsockopt(fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue)) < 0) {
		fprintf(stderr, "Can't set repair queue");
		return -1;
	}

	if (setsockopt(fd, SOL_TCP, TCP_QUEUE_SEQ, &seq, sizeof(seq)) < 0) {
		fprintf(stderr, "Can't set queue seq");
		return -1;
	}

	return 0;
}

static int __send_queue(int fd, const char *queue, char *buf, uint32_t len)
{
	//zlog_debug(zlog_handoff, "restoring TCP %s queue data %u bytes (rfd=%d)",
	//	queue, len, fd);

	int ret, err = -1, max_chunk;
	int off;

	max_chunk = len;
	off = 0;

	do {
		int chunk = len;

		if (chunk > max_chunk)
			chunk = max_chunk;

		ret = send(fd, buf + off, chunk, 0);
		if (ret <= 0) {
			if (max_chunk > 1024) {
				/*
				 * Kernel not only refuses the whole chunk,
				 * but refuses to split it into pieces too.
				 *
				 * When restoring recv queue in repair mode
				 * kernel doesn't try hard and just allocates
				 * a linear skb with the size we pass to the
				 * system call. Thus, if the size is too big
				 * for slab allocator, the send just fails
				 * with ENOMEM.
				 *
				 * In any case -- try smaller chunk, hopefully
				 * there's still enough memory in the system.
				 */
				max_chunk >>= 1;
				continue;
			}

			//zlog_fatal(zlog_handoff, "Can't restore %s queue data (%d), want (%d-%d:%d:%d)",
			//	queue, ret, off, chunk, len, max_chunk);
			goto err;
		}
		off += ret;
		len -= ret;
	} while (len);

	err = 0;
err:
	return err;
}

static int send_queue(int fd, int queue, char *buf, uint32_t len)
{
	if (setsockopt(fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue)) < 0) {
		//zlog_fatal(zlog_handoff, "Can't set repair queue");
		return -1;
	}

	return __send_queue(fd, queue == TCP_RECV_QUEUE ? "recv" : "send", buf, len);
}

static int restore_queue_recv(int fd, char *buf, int inq_len)
{
	if (!inq_len)
		return 0;
	return send_queue(fd, TCP_RECV_QUEUE, buf, inq_len);
}

static int restore_queue_send(int fd, char *buf, int outq_len, int unsq_len)
{
	/*
		* All data in a write buffer can be divided on two parts sent
		* but not yet acknowledged data and unsent data.
		* The TCP stack must know which data have been sent, because
		* acknowledgment can be received for them. These data must be
		* restored in repair mode.
		*/
	uint32_t ulen = unsq_len;
	uint32_t len = outq_len - ulen;

	if (len && send_queue(fd, TCP_SEND_QUEUE, buf, len))
		return -2;

	if (ulen) {
		/*
			* The second part of data have never been sent to outside, so
			* they can be restored without any tricks.
			*/
		fprintf(stderr, "cannot handle not-send send queue now\n");
		exit(EXIT_FAILURE);
		int ret = setsockopt(fd, IPPROTO_TCP, TCP_REPAIR, &(int){-1}, sizeof(int));
		assert(ret == 0);
		if (__send_queue(fd, "not-sent send", buf + len, ulen))
			return -3;
		ret = setsockopt(fd, IPPROTO_TCP, TCP_REPAIR, &(int){1}, sizeof(int));
		assert(ret == 0);
	}

	return 0;
}

void handoff_in_deserialize(struct handoff_in *in_ctx, SocketSerialize *migration_info, ngx_log_t *log)
{
	int ret = -1;

	int rfd;
	struct sockaddr_in server_sin, client_sin;
	struct tcp_repair_opt opts[4];

	struct tls12_crypto_info_aes_gcm_256 *crypto_info_send;
	struct tls12_crypto_info_aes_gcm_256 *crypto_info_recv;
	//size_t retry = 0;
//retry:
	/* restore tcp connection */
	errno = 0;

	rfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert(rfd > 0);
	assert(errno == 0);
	
	ret = setsockopt(rfd, IPPROTO_TCP, TCP_REPAIR, &(int){1}, sizeof(int));
	assert(ret == 0);
	assert(errno == 0);

	//ret = setsockopt(rfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
	//assert(ret == 0);
	//assert(errno == 0);
	//ret = setsockopt(rfd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int));
	//assert(ret == 0);
	//assert(errno == 0);

	server_sin.sin_family = AF_INET;
	if (migration_info->msg_type == HANDOFF_BACK_REQUEST || migration_info->msg_type == HANDOFF_RESET_REQUEST)
		server_sin.sin_port = htons(ntohs(migration_info->self_port) - 1 - 1);
	else
		server_sin.sin_port = migration_info->self_port;

	server_sin.sin_addr.s_addr = in_ctx->ngx_conf->my_sockaddr.sin_addr.s_addr;
	ret = bind(rfd, (struct sockaddr *)&server_sin, sizeof(server_sin));
	if (ret != 0) {
		ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0, "restored socket fail to bind : %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	//assert(ret == 0);
	//assert(errno == 0);

	ret = set_queue_seq(rfd, TCP_RECV_QUEUE, migration_info->ack - migration_info->recvq.len);
	assert(ret == 0);
	assert(errno == 0);

	ret = set_queue_seq(rfd, TCP_SEND_QUEUE,  migration_info->seq - migration_info->sendq.len);
	assert(ret == 0);
	assert(errno == 0);

	client_sin.sin_family = AF_INET;
	client_sin.sin_port = migration_info->peer_port;
	client_sin.sin_addr.s_addr = migration_info->peer_addr;
	ret = connect(rfd, (struct sockaddr *)&client_sin, sizeof(client_sin));
	assert(ret == 0);
	assert(errno == 0);

	bzero(opts, sizeof(opts));
	opts[0].opt_code = TCPOPT_SACK_PERM;
	opts[0].opt_val = 0;
	opts[1].opt_code = TCPOPT_WINDOW;
	opts[1].opt_val = migration_info->send_wscale + (migration_info->recv_wscale << 16);
	opts[2].opt_code = TCPOPT_TIMESTAMP;
	opts[2].opt_val = 0;
	opts[3].opt_code = TCPOPT_MSS;
	opts[3].opt_val = migration_info->mss;

	ret = setsockopt(rfd, IPPROTO_TCP, TCP_REPAIR_OPTIONS, opts, sizeof(struct tcp_repair_opt) * 4);
	assert(ret == 0);
	assert(errno == 0);
	ret = setsockopt(rfd, IPPROTO_TCP, TCP_TIMESTAMP, &migration_info->timestamp, sizeof(migration_info->timestamp));
	assert(ret == 0);
	assert(errno == 0);

	//ret = restore_queue_recv(rfd, (const uint8_t *)migration_info->recvq.data,
	ret = restore_queue_recv(rfd, (char *)migration_info->recvq.data,
		migration_info->recvq.len);
	assert(ret == 0);
	assert(errno == 0);
	//ret = restore_queue_send(rfd, (const uint8_t *)migration_info->sendq.data,
	ret = restore_queue_send(rfd, (char *)migration_info->sendq.data,
		migration_info->sendq.len, migration_info->unsentq_len);
	assert(ret == 0);
	assert(errno == 0);

	struct tcp_repair_window wopt = {
		.snd_wl1 = migration_info->snd_wl1,
		.snd_wnd = migration_info->snd_wnd,
		.max_window = migration_info->max_window,
		.rcv_wnd = migration_info->rev_wnd,
		.rcv_wup = migration_info->rev_wup,
	};
	ret = setsockopt(rfd, IPPROTO_TCP, TCP_REPAIR_WINDOW, &wopt, sizeof(wopt));
	assert(ret == 0);
	assert(errno == 0);

	const struct linger nolinger = { .l_onoff = 1, .l_linger = 0 };
	ret = setsockopt(rfd, SOL_SOCKET, SO_LINGER, &nolinger, sizeof nolinger);
	assert(ret == 0);

	//int error = 0;
	//socklen_t len = sizeof (error);
	//ret = getsockopt(rfd, SOL_SOCKET, SO_ERROR, &error, &len);
	//if (ret != 0) {
	//	/* there was a problem getting the error code */
	//	zlog_error(zlog_handoff, "Error getting socket error code: %s\n", strerror(ret));
	//	return;
	//}
	
	///* socket has a non zero error status */
	////zlog_notice(zlog_handoff, "Repaired socket state: %s\n", strerror(error));

	struct tcp_info_sub info;
	socklen_t slen = sizeof(info);
	ret = getsockopt(rfd, IPPROTO_TCP, TCP_INFO, &info, &slen);
	assert(ret == 0);
	if (info.tcpi_state != TCP_ESTABLISHED) {
		//zlog_notice(zlog_handoff, "TCP repair mode socket not established");
	}

	if (migration_info->ktlsbuf.len != 0) {
		if (migration_info->ktlsbuf.len != 2 * sizeof(struct tls12_crypto_info_aes_gcm_256)) {
			//zlog_fatal(zlog_tls, "incorrect ktlsbuf length (%ld)", migration_info->ktlsbuf.len);
			exit(EXIT_FAILURE);
		}
		crypto_info_send = (struct tls12_crypto_info_aes_gcm_256 *)migration_info->ktlsbuf.data;
		crypto_info_recv = (struct tls12_crypto_info_aes_gcm_256 *)migration_info->ktlsbuf.data + sizeof(struct tls12_crypto_info_aes_gcm_256);
		
		if (setsockopt(rfd, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) < 0) {
			if (info.tcpi_state != TCP_ESTABLISHED) {
				//zlog_fatal(zlog_tls, "set ULP tls fail (%s). it was previously not TCP_ESTABLISHED (peer_port=%d)", strerror(errno), ntohs(migration_info->peer_port));
			}
			else {
				//zlog_fatal(zlog_tls, "set ULP tls fail (%s). it was previously TCP_ESTABLISHED (peer_port=%d)", strerror(errno), ntohs(migration_info->peer_port));
			}
			fflush(stdout);
			exit(EXIT_FAILURE);
		}
		if (setsockopt(rfd, SOL_TLS, TLS_TX, crypto_info_send,
						sizeof(*crypto_info_send)) < 0) {
			//zlog_fatal(zlog_tls, "Couldn't set TLS_TX option (%s)", strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (setsockopt(rfd, SOL_TLS, TLS_RX, crypto_info_recv,
						sizeof(*crypto_info_recv)) < 0) {
			//zlog_fatal(zlog_tls, "Couldn't set TLS_RX option (%s)", strerror(errno));
			exit(EXIT_FAILURE);
		}
		//zlog_debug(zlog_handoff, "Added kTLS state to socket");
	}

	/* quiting repair mode */
	ret = setsockopt(rfd, IPPROTO_TCP, TCP_REPAIR, &(int){-1}, sizeof(int));
	assert(ret == 0);

	// make sure repair is blocking
	set_socket_non_blocking(rfd);

	//ret = setsockopt(rfd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int));
	//assert(ret == 0);

	struct http_client *client = create_http_client(in_ctx->epoll_fd, rfd);
	snprintf(client->bucket_name, MAX_BUCKET_NAME_SIZE, "%s", migration_info->bucket_name);
	snprintf(client->object_name, MAX_OBJECT_NAME_SIZE, "%s", migration_info->object_name);
	//client->uri_str = realloc(client->uri_str, sizeof(char) * (strlen(migration_info->uri_str) + 1));
	snprintf(client->uri_str, strlen(migration_info->uri_str) + 1, "%s", migration_info->uri_str);
	client->object_size = migration_info->object_size;
	//client->method = migration_info->method;
	//client->bucket_io_ctx = in_ctx->bucket_io_ctx;
	//client->data_io_ctx = in_ctx->data_io_ctx;
	if (migration_info->msg_type == HANDOFF_REQUEST) {
		client->from_migrate = in_ctx->osd_arr_index;
	}
        else {
		client->from_migrate = -1;
	}

	memcpy(client->client_mac, &(migration_info->peer_mac), sizeof(uint8_t) * 6);

	if (migration_info->ktlsbuf.len) {
		client->tls.is_ssl = true;
		client->tls.is_handshake_done = true;
		client->tls.is_ktls_set = true;
	} else {
		client->tls.is_ssl = false;
	}

	client->client_addr = migration_info->peer_addr;
	client->client_port = migration_info->peer_port;

	client->fd = rfd;

//	if ((migration_info->msg_type == HANDOFF_BACK_REQUEST && migration_info->acting_primary_osd_id == get_my_osd_id()) || migration_info->msg_type == HANDOFF_REQUEST) {
//		ret = rados_aio_wait_for_complete(comp);
//		assert(ret == 0);
//		rados_aio_release(comp);
//		client->object_size = psize;
//		migration_info->object_size = psize;
//	}

	//zlog_debug(zlog_handoff, "Deserialized: %s (size=%ld) (fd=%d,port=%d)", client->uri_str, psize, client->fd, client->client_port);

	// we only add client into epoll after originaldone received
	in_ctx->client_for_originaldone = client;
}

//int handoff_in_listen(int thread_id)
//{
//	struct sockaddr_in saddr = {0};
//	saddr.sin_family = AF_INET;
//	saddr.sin_addr.s_addr = INADDR_ANY;
//	saddr.sin_port = htons(HANDOFF_CTRL_PORT + thread_id);
//
//	int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
//	if (listen_fd == -1) {
//		zlog_error(zlog_handoff, "Failed to create incoming handoff listener socket: %s", strerror(errno));
//		return -1;
//	}
//
//	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int))) {
//		zlog_error(zlog_handoff, "Failed to setsockopt SO_REUSEADDR: %s", strerror(errno));
//		return -1;
//	}
//
//	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int))) {
//		zlog_error(zlog_handoff, "Failed to setsockopt SO_REUSEPORT: %s", strerror(errno));
//		return -1;
//	}
//
//	if (bind(listen_fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
//		zlog_error(zlog_handoff, "Failed to bind socket: %s", strerror(errno));
//		return -1;
//	}
//
//	if (listen(listen_fd, SOMAXCONN) < 0) {
//		zlog_error(zlog_handoff, "Failed to listen (fd=%d): %s", listen_fd, strerror(errno));
//		return -1;
//	}
//
//	set_socket_non_blocking(listen_fd);
//
//	return listen_fd;
//}
//
//// no need to change epoll since we will need to wait for new migration request
//// anyways
//static void handoff_in_recv_done(struct handoff_in *in_ctx) {
//
//	//zlog_debug(zlog_handoff, "HANDOFF_IN Recevied ready to redirect message from original server (osd=%d,in_ctx->fd=%d)", osd_ids[in_ctx->osd_arr_index], in_ctx->fd);
//
//	struct http_client *client = in_ctx->client_for_originaldone;
//
//	struct epoll_event event = {};
//	event.data.ptr = client;
//	event.events = EPOLLIN | EPOLLRDHUP;
//	int ret = epoll_ctl(client->epoll_fd, EPOLL_CTL_ADD, client->fd, &event);
//	assert(ret == 0);
//
//	// check if HTTP GET
//	char datetime_str[256];
//	get_datetime_str(datetime_str, 256);
//
//	init_object_get_request(client);
//	complete_get_request(client, datetime_str);
//
//	in_ctx->client_for_originaldone = NULL;
//}
//
//// handle handoff request - another end will not send another
//// request before current request is been acked
//// 1. loop until whole request received
//// 2. create a new http client, deserialze s3 client,
//// create connect, setup ktls
//// 3. change mod to epoll out and send back handoff done
//void handoff_in_recv(struct handoff_in *in_ctx, bool *ready_to_send, struct http_client **client_to_handoff_again) {
//	*ready_to_send = false;
//	*client_to_handoff_again = NULL;
//
//	if (in_ctx->recv_protobuf == NULL) {
//		int ret = recv(in_ctx->fd, &in_ctx->recv_protobuf_len, sizeof(in_ctx->recv_protobuf_len), 0);
//		if ((ret == 0) || (ret == -1 && errno != EAGAIN)) {
//			zlog_error(zlog_handoff, "Fail to receive incoming handoff protobuf message length: %s", strerror(errno));
//			handoff_in_disconnect(in_ctx);
//			return;
//		}
//		if (ret == -1 && errno == EAGAIN) {
//			return;
//		}
//		if (ret != sizeof(in_ctx->recv_protobuf_len)) {
//			//zlog_fatal(zlog_handoff, "unable to handle the case TCP recv not equal to 4 bytes on header");
//			exit(EXIT_FAILURE);
//		}
//
//		// received original done
//		if (in_ctx->recv_protobuf_len == UINT32_MAX) {
//			ready_to_send = false; // nothing to send...
//			// this can be NULL for handoff_reset or handoff_back_rehandoff
//			if (in_ctx->client_for_originaldone != NULL)
//				handoff_in_recv_done(in_ctx);
//			if (in_ctx->client_to_handoff_again) {
//				*client_to_handoff_again = in_ctx->client_to_handoff_again;
//				in_ctx->client_to_handoff_again = NULL;
//			}
//			in_ctx->recv_protobuf_len = 0;
//			in_ctx->wait_for_originaldone = false;
//			return;
//		}
//
//		if (in_ctx->wait_for_originaldone) {
//			// we are waiting for original done
//			// but we didn't receive it, but a new migration
//			//zlog_fatal(zlog_handoff, "HANDOFF_IN new migration comes before original server done (osd=%d)",	osd_ids[in_ctx->osd_arr_index]);
//			exit(EXIT_FAILURE);
//		}
//
//		in_ctx->recv_protobuf_len = ntohl(in_ctx->recv_protobuf_len);
//		if (in_ctx->recv_protobuf_len == 0) {
//			//zlog_fatal(zlog_handoff, "in_ctx->recv_protobuf_len is zero");
//			exit(EXIT_FAILURE);
//		}
//		in_ctx->recv_protobuf = malloc(in_ctx->recv_protobuf_len);
//	}
//
//	int ret = recv(in_ctx->fd, in_ctx->recv_protobuf + in_ctx->recv_protobuf_received,
//		in_ctx->recv_protobuf_len - in_ctx->recv_protobuf_received, 0);
//	if ((ret == 0) || (ret == -1 && errno != EAGAIN)) {
//		zlog_error(zlog_handoff, "Fail to receive protobuf message: %s", strerror(errno));
//		handoff_in_disconnect(in_ctx);
//		return;
//	}
//	if (ret == -1 && errno == EAGAIN) {
//		return;
//	}
//
//	SocketSerialize *migration_info = socket_serialize__unpack(NULL,
//		in_ctx->recv_protobuf_len, in_ctx->recv_protobuf);
//
//	if (in_ctx->recv_protobuf != NULL) {
//		free(in_ctx->recv_protobuf);
//		in_ctx->recv_protobuf = NULL;
//	}
//	in_ctx->recv_protobuf_len = 0;
//	in_ctx->recv_protobuf_received = 0;
//
//	if (migration_info->msg_type == HANDOFF_REQUEST) {
//		handoff_in_deserialize(in_ctx, migration_info);
//		//zlog_debug(zlog_handoff, "HANDOFF_IN HANDOFF_REQUEST Deserialize connection (in_ctx->fd=%d)", in_ctx->fd);
//		// apply src IP modification
//		//if (use_tc) {
//		//	ret = apply_redirection(get_my_osd_addr().sin_addr.s_addr, migration_info->peer_addr,
//		//				migration_info->self_port, migration_info->peer_port,
//		//				migration_info->self_addr, my_mac, migration_info->peer_addr, (uint8_t *)&migration_info->peer_mac,
//		//				htons(ntohs(migration_info->self_port) - osd_ids[in_ctx->osd_arr_index] - 1), migration_info->peer_port, false, false); // offst self port
//		//} else {
//			ret = apply_redirection_ebpf(get_my_osd_addr().sin_addr.s_addr, migration_info->peer_addr,
//						migration_info->self_port, migration_info->peer_port,
//						migration_info->self_addr, my_mac, migration_info->peer_addr, (uint8_t *)&migration_info->peer_mac,
//						htons(ntohs(migration_info->self_port) - osd_ids[in_ctx->osd_arr_index] - 1), migration_info->peer_port, false); // offst self port
//		//}
//		assert(ret == 0);
//		//zlog_debug(zlog_handoff, "HANDOFF_IN HANDOFF_REQUEST Applied source IP modification (in_ctx->fd=%d)", in_ctx->fd);
//	} else if (migration_info->msg_type == HANDOFF_BACK_REQUEST) {
//		if (migration_info->acting_primary_osd_id == get_my_osd_id()) {
//			//zlog_debug(zlog_handoff, "HANDOFF_IN HANDOFF_BACK_REQUEST Migration target is current node, deserialize (in_ctx->fd=%d)", in_ctx->fd);
//			handoff_in_deserialize(in_ctx, migration_info);
//			// we are safe to remove previous redir to fake server there since we
//			// either have a working fd or blocked incoming packets
//			if (use_tc && !tc_hybrid) {
//				ret = remove_redirection(migration_info->peer_addr, get_my_osd_addr().sin_addr.s_addr,
//							migration_info->peer_port, htons(ntohs(migration_info->self_port) - get_my_osd_id() - 1));
//				assert(ret == 0);
//			}
//			else {
//				if (tc_hybrid) {
//					if (!rule_in_queue(migration_info->peer_addr, get_my_osd_addr().sin_addr.s_addr, migration_info->peer_port, htons(ntohs(migration_info->self_port) - get_my_osd_id() - 1), q)) {
//						while ((ret = remove_redirection(migration_info->peer_addr, get_my_osd_addr().sin_addr.s_addr,
//							migration_info->peer_port, htons(ntohs(migration_info->self_port) - get_my_osd_id() - 1))) != 0) { } 
//					}
//				}
//				ret = remove_redirection_ebpf(migration_info->peer_addr, get_my_osd_addr().sin_addr.s_addr,
//							migration_info->peer_port, htons(ntohs(migration_info->self_port) - get_my_osd_id() - 1));
//				assert(ret == 0);
//			}
//		} else {
//			//zlog_debug(zlog_handoff, "HANDOFF_IN HANDOFF_BACK_REQUEST Migration target is not current node, rehandoff to target (osd=%d,in_ctx->fd=%d)",
//				migration_info->acting_primary_osd_id, in_ctx->fd);
//
//			// eBPF blocking rule applied here
//			handoff_out_serialize_rehandoff(&in_ctx->client_to_handoff_again, migration_info);
//			// we are safe to remove previous redir to fake server there since we
//			// either have a working fd or blocked incoming packets
//			// don't remove eBPF because redir rule should be rewritten to block rule by handoff_out_serialize_rehandoff
//			if (use_tc && !tc_hybrid) {
//				ret = remove_redirection(migration_info->peer_addr, get_my_osd_addr().sin_addr.s_addr,
//							migration_info->peer_port, htons(ntohs(migration_info->self_port) - get_my_osd_id() - 1));
//				assert(ret == 0);
//			}
//			else if (use_tc && tc_hybrid) {
//				if (!rule_in_queue(migration_info->peer_addr, get_my_osd_addr().sin_addr.s_addr, migration_info->peer_port, htons(ntohs(migration_info->self_port) - get_my_osd_id() - 1), q)) {
//					while ((ret = remove_redirection(migration_info->peer_addr, get_my_osd_addr().sin_addr.s_addr,
//						migration_info->peer_port, htons(ntohs(migration_info->self_port) - get_my_osd_id() - 1))) != 0) { }
//				}
//			}
//		}
//		// we are safe to remove previous redir to fake server there since we
//		// either have a working fd or blocked incoming packets
//		//zlog_debug(zlog_handoff, "HANDOFF_IN HANDOFF_BACK_REQUEST Remove redirection rule from client to fake server (osd=%d,client=%" PRIu64":%d,original_server=%" PRIu64":%d)",
//					osd_ids[in_ctx->osd_arr_index],
//					migration_info->peer_addr, ntohs(migration_info->peer_port),
//					migration_info->self_addr, ntohs(migration_info->self_port) - get_my_osd_id() - 1);
//	} else if (migration_info->msg_type == HANDOFF_RESET_REQUEST) {
//		if (use_tc && !tc_hybrid) {
//			ret = remove_redirection(migration_info->peer_addr, get_my_osd_addr().sin_addr.s_addr,
//						migration_info->peer_port, htons(ntohs(migration_info->self_port) - get_my_osd_id() - 1));
//			assert(ret == 0);
//		}
//		else {
//			if (tc_hybrid) {
//				if (!rule_in_queue(migration_info->peer_addr, get_my_osd_addr().sin_addr.s_addr, migration_info->peer_port, htons(ntohs(migration_info->self_port) - get_my_osd_id() - 1), q)) {
//					while ((ret = remove_redirection(migration_info->peer_addr, get_my_osd_addr().sin_addr.s_addr,
//						migration_info->peer_port, htons(ntohs(migration_info->self_port) - get_my_osd_id() - 1))) != 0) { }
//					assert(ret == 0);
//				}
//			}
//
//			ret = remove_redirection_ebpf(migration_info->peer_addr, get_my_osd_addr().sin_addr.s_addr,
//						migration_info->peer_port, htons(ntohs(migration_info->self_port) - get_my_osd_id() - 1));
//			assert(ret == 0);
//		}
//		//zlog_debug(zlog_handoff, "HANDOFF_IN HANDOFF_RESET_REQUEST Remove redirection rule from client to fake server (osd=%d,client=%" PRIu64":%d,orignal_server=%" PRIu64":%d)",
//				osd_ids[in_ctx->osd_arr_index],
//				migration_info->peer_addr, ntohs(migration_info->peer_port),
//				migration_info->self_addr, ntohs(migration_info->self_port) - get_my_osd_id() - 1);
////exit(1);
//	} else {
//		//zlog_fatal(zlog_handoff, "Can only handle HANDOFF_REQUEST or HANDOFF_BACK_REQUEST msg");
//		exit(EXIT_FAILURE);
//	}
//
//	// build response proto_buf
//	SocketSerialize migration_info_resp = SOCKET_SERIALIZE__INIT;
//	migration_info_resp.msg_type = HANDOFF_DONE;
//
//	migration_info_resp.self_addr = migration_info->self_addr;
//	migration_info_resp.peer_addr = migration_info->peer_addr;
//
//	// encode self mac in response for orginal server to perform redirection
//	memcpy(&(migration_info_resp.peer_mac), my_mac, sizeof(uint8_t) * 6);
//
//	// reply object size for original server to determine redirection method
//	migration_info_resp.object_size = migration_info->object_size;
//	migration_info_resp.self_port = migration_info->self_port;
//	migration_info_resp.peer_port = migration_info->peer_port;
//
//	// no longer need
//	socket_serialize__free_unpacked(migration_info, NULL);
//
//	int proto_len = socket_serialize__get_packed_size(&migration_info_resp);
//	uint32_t net_proto_len = htonl(proto_len);
//	uint8_t *proto_buf = malloc(sizeof(net_proto_len) + proto_len);
//	socket_serialize__pack(&migration_info_resp, proto_buf + sizeof(net_proto_len));
//	// add length of proto_buf at the begin
//	memcpy(proto_buf, &net_proto_len, sizeof(net_proto_len));
//
//	// change epoll to epollout
//	in_ctx->send_protobuf = proto_buf;
//	in_ctx->send_protobuf_len = sizeof(net_proto_len) + proto_len;
//	in_ctx->send_protobuf_sent = 0;
//	struct epoll_event event = {0};
//	event.data.ptr = in_ctx;
//	event.events = EPOLLOUT | EPOLLRDHUP;
//	if (epoll_ctl(in_ctx->epoll_fd, EPOLL_CTL_MOD, in_ctx->fd, &event) == -1) {
//		//zlog_fatal(zlog_handoff, "Failed to change socket in_ctx->fd=%d to send mode: %s", in_ctx->fd, strerror(errno));
//		exit(EXIT_FAILURE);
//	}
//
//	*ready_to_send = true;
//}
//
//void handoff_in_send(struct handoff_in *in_ctx) {
//	int ret = send(in_ctx->fd, in_ctx->send_protobuf + in_ctx->send_protobuf_sent,
//		in_ctx->send_protobuf_len - in_ctx->send_protobuf_sent, 0);
//	if ((ret == 0) || (ret == -1 && errno != EAGAIN)) {
//		//zlog_fatal(zlog_handoff, "Failed to send protobuf len in_ctx->fd=%d: %s", in_ctx->fd, strerror(errno));
//		handoff_in_disconnect(in_ctx);
//		return;
//	}
//	if (ret == -1 && errno == EAGAIN) {
//		return;
//	}
//
//	in_ctx->send_protobuf_sent += ret;
//
//	if (in_ctx->send_protobuf_sent < in_ctx->send_protobuf_len) {
//		//zlog_debug(zlog_handoff, "HANDOFF_IN sent response to migration request %d/%d (osd=%d,in_ctx->fd=%d)",
//			in_ctx->send_protobuf_sent, in_ctx->send_protobuf_len, osd_ids[in_ctx->osd_arr_index], in_ctx->fd);
//		return;
//	}
//	//zlog_debug(zlog_handoff, "HANDOFF_IN all response to migration request sent (osd=%d,in_ctx->fd=%d)", osd_ids[in_ctx->osd_arr_index], in_ctx->fd);
//
//	// send done
//	if (in_ctx->send_protobuf != NULL) {
//		free(in_ctx->send_protobuf);
//		in_ctx->send_protobuf = NULL;
//	}
//	in_ctx->send_protobuf_len = 0;
//	in_ctx->send_protobuf_sent = 0;
//	in_ctx->wait_for_originaldone = true;
//	struct epoll_event event = {0};
//	event.data.ptr = in_ctx;
//	event.events = EPOLLIN | EPOLLRDHUP;
//	if (epoll_ctl(in_ctx->epoll_fd, EPOLL_CTL_MOD, in_ctx->fd, &event) == -1) {
//		//zlog_fatal(zlog_handoff, "Fail to set socket back to receive mode (in_ctx->fd=%d): %s", in_ctx->fd, strerror(errno));
//		exit(EXIT_FAILURE);
//	}
//}
//
//void handoff_in_disconnect(struct handoff_in *in_ctx)
//{
//	//zlog_info(zlog_handoff, "Disconnecting incoming handoff control socket (in_ctx->fd=%d)", in_ctx->fd);
//	close(in_ctx->fd);
//	in_ctx->fd = 0;
//}
