//#include <numa.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <string.h>

#include <errno.h>
#include <sys/epoll.h>
#include <sys/uio.h>

#include "http_client.h"
#include <netinet/tcp.h>
#include <arpa/inet.h>

//#include "zlog.h"

bool enable_migration = false;
//zlog_category_t *zlog_object_store;

int send_client_data(struct http_client *client)
{
	struct iovec iov[2];
	size_t iov_count = 0;

	if (client->response_sent != client->response_size) {
		iov[iov_count].iov_base = client->response + client->response_sent;
		iov[iov_count].iov_len = client->response_size - client->response_sent;
		iov_count++;
	}

	if (client->data_payload_sent != client->data_payload_ready) {
		iov[iov_count].iov_base = client->data_payload + client->data_payload_sent;
		iov[iov_count].iov_len = client->data_payload_ready - client->data_payload_sent;
		iov_count++;
	}

	ssize_t ret = writev(client->fd, iov, iov_count);
	if (ret > 0) {
		// response is not complete sent
		if (client->response_sent != client->response_size) {
			ssize_t response_left = client->response_size - client->response_sent;
			if (ret > response_left) {
				client->response_sent = client->response_size;
				ret -= response_left;
			}
			else {
				client->response_sent += ret;
				ret = 0;
			}
		}

		client->data_payload_sent += ret;
		//zlog_debug(zlog_object_store, "writev ret=%ld (fd=%d,port=%d) called (%ld/%ld,%ld/%ld/%ld)", ret, client->fd, ntohs(client->client_port), client->response_sent, client->response_size, client->data_payload_sent, client->data_payload_ready, client->data_payload_size);
	} else {
		if (ret == 0 || (ret == -1 && errno != EAGAIN)) {
			//zlog_error(zlog_object_store, "writev returned %ld on (fd=%d,port=%d) (%s)\n", ret, client->fd, ntohs(client->client_port), strerror(errno));
			return -1;
		}
	}

	/* all currently avaliable payload sent, stop triggering */
	if (client->response_size == client->response_sent && client->data_payload_ready == client->data_payload_sent) {
		struct epoll_event event = {};
		event.data.ptr = client;
		event.events = EPOLLIN;

		epoll_ctl(client->epoll_fd, EPOLL_CTL_MOD, client->fd, &event);
	}

	/* all payload sent */
	if (client->response_size == client->response_sent && client->data_payload_size == client->data_payload_sent) {
		reset_http_client(client);
	}

	return 0;
}

void send_response(struct http_client *client)
{
	struct epoll_event event = {};
	event.data.ptr = client;
	//event.data.u32 = client->epoll_data_u32;
	event.events = EPOLLOUT | EPOLLRDHUP;
	int ret = epoll_ctl(client->epoll_fd, EPOLL_CTL_MOD, client->fd, &event);
	assert(ret == 0);
}

//void aio_ack_callback(rados_completion_t comp, void *arg) {
//}
//
//void aio_commit_callback(rados_completion_t comp, void *arg) {
//	struct http_client *client = (struct http_client*)arg;
//	send_response(client);
//}

void reset_http_client(struct http_client *client)
{
//	if (client->aio_in_progress && !rados_aio_is_complete_and_cb(client->aio_head_read_completion)) {
//		rados_aio_cancel(client->data_io_ctx, client->aio_head_read_completion);
//		rados_aio_wait_for_complete_and_cb(client->aio_head_read_completion);
//		//zlog_debug(zlog_object_store,"finishing aio");
//	}
//	if (client->aio_in_progress && !rados_aio_is_complete_and_cb(client->aio_completion)) {
//		rados_aio_cancel(client->data_io_ctx, client->aio_completion);
//		rados_aio_wait_for_complete_and_cb(client->aio_completion);
//		//zlog_debug(zlog_object_store,"finishing aio");
//	}
	//if (!rados_aio_is_complete_and_cb(client->aio_completion)) {
	//}
	//rados_aio_wait_for_complete(client->aio_completion);
	client->to_migrate = -1;
	client->acting_primary_osd_id = -1;
	client->proto_buf_sent = 0;
	client->proto_buf_len = 0;
	if (client->proto_buf != NULL) {
		free(client->proto_buf);
		client->proto_buf = NULL;
	}

	client->num_fields = 0;
	client->expect = NONE;

	client->uri_str_len = 0;
	memset(client->bucket_name, 0, 64);
	memset(client->object_name, 0, 1025);

	client->object_offset = 0;

	client->response_size = 0;
	client->response_sent = 0;

	client->data_payload_size = 0;
	client->data_payload_sent = 0;

	client->prval = 0;
	client->object_size = 0;
	client->parsing = false;
	client->deleting = false;
	client->chunked_upload = false;

	client->header_field_parsed = 0;
	client->header_value_parsed = 0;

//	llhttp_finish(&(client->parser));
//
//	llhttp_settings_init(&(client->settings));
//	llhttp_init(&(client->parser), HTTP_BOTH, &(client->settings));
}

struct http_client *create_http_client(int epoll_fd, int fd)
{
	struct http_client *client = (struct http_client*)calloc(1, sizeof(struct http_client));
	//struct http_client *client;
	//posix_memalign(&client, 64, sizeof(struct http_client));
//printf("%d\n", sizeof(struct http_client));
//exit(1);
	//struct http_client *client = (struct http_client*)numa_alloc_local(sizeof(struct http_client) + 33*sizeof(char));
	memset(client, 0, sizeof(struct http_client));

	//llhttp_settings_init(&(client->settings));
	//llhttp_init(&(client->parser), HTTP_BOTH, &(client->settings));

	//client->settings.on_message_complete = on_message_complete_cb;
	//client->settings.on_header_field = on_header_field_cb;
	//client->settings.on_header_value = on_header_value_cb;
	//client->settings.on_headers_complete = on_headers_complete_cb;
	//client->settings.on_url = on_url_cb;
	//client->settings.on_url_complete = on_url_complete_cb;
	//client->settings.on_reset = on_reset_cb;
	//client->settings.on_body = on_body_cb;

	//client->data_payload = numa_alloc_local(sizeof(char)*1024*1024*4);
	client->put_buf = malloc(0);
	//client->data_payload = malloc(0);
	//client->response = NULL;
	//client->uri_str = malloc(0);

//	client->header_fields = (char**)malloc(sizeof(char*) * MAX_FIELDS);
//	client->header_values = (char**)malloc(sizeof(char*) * MAX_FIELDS);

	//client->write_op = rados_create_write_op();
	//client->read_op = rados_create_read_op();
	//rados_aio_create_completion((void*)client, NULL, NULL, &(client->aio_completion));
	//rados_aio_create_completion((void*)client, NULL, NULL, &(client->aio_head_read_completion));
	client->aio_in_progress = 0;

	//client->bucket_io_ctx = NULL;
	//client->data_io_ctx = NULL;

	client->prval = 0;
	client->from_migrate = -1;
	reset_http_client(client);

	client->tls.is_ssl = true;
	client->tls.is_handshake_done = false;
	client->tls.is_ktls_set = false;
	client->tls.ssl = NULL;
	client->tls.rbio = NULL;
	client->tls.wbio = NULL;
	client->tls.client_hello_check_off = false;
	client->tls.is_client_traffic_secret_set = false;
	client->tls.is_server_traffic_secret_set = false;


	client->epoll_fd = -1;
	//client->epoll_fd = epoll_fd;
	client->epoll_data_u32 = 0;
	client->fd = fd;
	//client->parser.data = client;

	return client;
}

void free_http_client(struct http_client *client)
{
//	llhttp_finish(&(client->parser));
	reset_http_client(client);

//	free(client->header_fields);
//	free(client->header_values);
	//free(client->uri_str);
	//numa_free(client->data_payload, 1024*1024*4);
	free(client->put_buf);

	//rados_aio_release(client->aio_head_read_completion);
	//rados_aio_release(client->aio_completion);
	//rados_release_write_op(client->write_op);
	//rados_release_read_op(client->read_op);

	//numa_free(client, sizeof(struct http_client));
	free(client);
}
