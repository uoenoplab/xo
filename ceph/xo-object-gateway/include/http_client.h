#ifndef __HTTP_CLIENT_H__
#define __HTTP_CLIENT_H__

#include <rados/librados.h>
#include <uriparser/Uri.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <llhttp.h>

#include "md5.h"
#include "util.h"

#define MAX_HTTP_CLIENTS 1000

#define BUCKET_POOL "bucket_pool"
#define DATA_POOL "data_pool"

// including null char
#define MAX_RESPONSE_SIZE 8193
#define MAX_BUCKET_NAME_SIZE 64
#define MAX_OBJECT_NAME_SIZE 1025
#define MAX_FIELDS 32
#define MAX_FIELDS_SIZE 4096

enum http_expect { CONTINUE, NONE };

extern const size_t BUF_SIZE;
#ifdef USE_MIGRATION
extern bool enable_migration;
#endif

typedef struct ssl_st SSL;
typedef struct bio_st BIO;

static char *HTTP_OK_HDR = (char *)"HTTP/1.1 200 OK\r\n"
		 "Connection: keep-alive\r\n"
		 "Server: Apache/2.2.800";

static char *HTTP_NOT_FOUND_HDR = (char *)"HTTP/1.1 404 NOT FOUND\r\n"
		 "Connection: keep-alive\r\n"
		 "Server: Apache/2.2.800";

static char *HTTP_CONTINUE_HDR = (char *)"HTTP/1.1 100 CONTINUE\r\n\r\n";

static char *AMZ_REQUEST_ID = (char*)"tx000009a75d393f1564ec2-0065202454-3771-default";

struct http_client {
	uint32_t epoll_data_u32;
	// always set epoll.data.u32 to this value
	int fd;
	int epoll_fd;

	int prval;
	rados_xattrs_iter_t iter;
	rados_completion_t comp;
	rados_read_op_t read_op;
	rados_read_op_t write_op;

	ssize_t data_payload_sent;
	ssize_t data_payload_size;
	ssize_t data_payload_ready;
	//char *data_payload;
	char data_payload[8 * 1024 * 1024];

	ssize_t response_sent;
	ssize_t response_size;
	//https://www.tutorialspoint.com/What-is-the-maximum-size-of-HTTP-header-values
	char response[MAX_RESPONSE_SIZE];

	llhttp_t parser;
	llhttp_settings_t settings;
	enum http_expect expect;
	enum llhttp_method method;

	// https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
	char bucket_name[MAX_BUCKET_NAME_SIZE];
	// https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html
	char object_name[MAX_OBJECT_NAME_SIZE];

	//char *uri_str;
	char uri_str[1024];
	size_t uri_str_len;
	//UriUriA uri;

	char header_fields[MAX_FIELDS][MAX_FIELDS_SIZE];
	char header_values[MAX_FIELDS][MAX_FIELDS_SIZE];

	size_t header_field_parsed;
	size_t header_value_parsed;
	//char **header_fields;
	//char **header_values;
	size_t num_fields;

	pthread_mutex_t mutex;
	rados_ioctx_t bucket_io_ctx;
	rados_ioctx_t data_io_ctx;
	rados_completion_t aio_completion;
	rados_completion_t aio_head_read_completion;
	int aio_in_progress;

	size_t object_size;
	size_t object_offset;
	char *put_buf;

	size_t http_payload_size;
	bool chunked_upload;
	bool parsing;
	bool deleting;

	size_t current_chunk_size;
	size_t current_chunk_offset;
	RollingMD5Context md5_ctx;

	xmlParserCtxtPtr xml_ctx;

	struct tls {
		bool is_ssl;
		bool is_handshake_done;
		bool is_ktls_set;

		SSL *ssl;

		BIO *rbio; /* SSL reads from, we write to. */
		BIO *wbio; /* SSL writes to, we read from. */

		int client_hello_check_off;
		unsigned char client_hello_check_buf[3];

		bool is_client_traffic_secret_set;
		bool is_server_traffic_secret_set;

		unsigned char client_traffic_secret[48];
		unsigned char server_traffic_secret[48];
	} tls;

	// handoff
	int to_migrate;
	int from_migrate;
	int acting_primary_osd_id;
	uint8_t client_mac[6];

	uint32_t client_addr;
	uint16_t client_port;

	uint8_t *proto_buf;
	uint32_t proto_buf_len; // include the uint32 header size
	uint32_t proto_buf_sent;
};

struct http_client *create_http_client(int epoll_fd, int fd);
void reset_http_client(struct http_client *client);
void free_http_client(struct http_client *client);

//static int on_header_field_cb(llhttp_t *parser, const char *at, size_t length);
//static int on_header_value_cb(llhttp_t *parser, const char *at, size_t length);
//static int on_body_cb(llhttp_t *parser, const char *at, size_t length);
//static int on_url_cb(llhttp_t *parser, const char *at, size_t length);
//
//static int on_headers_complete_cb(llhttp_t* parser);
//static int on_chunk_header(llhttp_t *parser);
//static int on_message_complete_cb(llhttp_t* parser);
//static int on_reset_cb(llhttp_t *parser);

void aio_ack_callback(rados_completion_t comp, void *arg);
void aio_commit_callback(rados_completion_t comp, void *arg);
int send_client_data(struct http_client *client);
void send_response(struct http_client *client);

#endif
