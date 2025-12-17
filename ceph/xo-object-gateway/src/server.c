#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/epoll.h>
#include <errno.h>
#include <sys/uio.h>
#include <pthread.h>
#include <assert.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <ini.h>
#include <netinet/tcp.h>
#include <net/if_arp.h>

#include "queue.h"
#include "http_client.h"
#include "tls.h"
#include "osd_mapping.h"
#include "object_store.h"

#include "handoff.h"

#define MAX_EVENTS 1000

enum THREAD_EPOLL_EVENT {
	S3_HTTP_EVENT,
	HANDOFF_IN_EVENT,
	HANDOFF_OUT_EVENT,
};

// 0.  handle incoming conn
// 1.  read
// 2.  check if we are reading from an ongoing HTTP message
// 2.1 create new entry
// 2.2 start populating http req structure
// 3.  check end of header. check if we need to respond right away
// 3.1 metadata req
// 3.1.1 talk to rados and reply
// 3.2 data put
// 3.2.1 setup asyn io context
// 3.3 data get
// 3.3.1 setup asyn io context
// 4.  read payload run io op with io context
// 5.  check end of payload
// 5.1 wait for async completion, respond http OK

const size_t BUF_SIZE = sizeof(char) * 1024 * 1024 * 8;

volatile sig_atomic_t server_running = 1;

char *osd_addr_strs[MAX_OSDS] = { NULL };
struct sockaddr_in osd_addrs[MAX_OSDS];
int osd_ids[MAX_OSDS] = { 0 };
int num_osds = 0;
int num_peers = 0;

uint8_t my_mac[6];

zlog_category_t *zlog_server;

struct thread_param {
	int thread_id;
	// int server_fd;
	rados_t cluster;
	char ifname[32];
};

void split_uint64_to_ints(uint64_t value, int *high, int *low) {
	*high = (int)(value >> 32);
	*low = (int)(value & 0xFFFFFFFF);
}

uint64_t combine_ints_to_uint64(int high, int low) {
	return ((uint64_t)high << 32) | (uint32_t)low;
}

void handleCtrlC(int signum)
{
	zlog_info(zlog_server, "Received Ctrl+C. Stopping the server thread [%d]...", gettid());
	server_running = 0; // Set the flag to stop the server gracefully.
}


#define MAC_CACHE_SIZE 10  // Smaller cache for simplicity

struct cache_entry {
    struct in_addr ip_addr; // IP address
    uint8_t mac[6];	 // MAC address
    int valid;	      // Validity flag to check if entry is used
};

struct cache_entry mac_cache[MAC_CACHE_SIZE] = {0};  // Cache initialization

static int get_mac_from_cache(struct in_addr ip_addr, uint8_t *mac) {
    for (int i = 0; i < MAC_CACHE_SIZE; i++) {
	if (mac_cache[i].valid && mac_cache[i].ip_addr.s_addr == ip_addr.s_addr) {
	    memcpy(mac, mac_cache[i].mac, sizeof(uint8_t)*6);
	    return 1; // MAC found in cache
	}
    }
    return 0; // Not found
}

static void add_mac_to_cache(struct in_addr ip_addr, uint8_t *mac) {
    for (int i = 0; i < MAC_CACHE_SIZE; i++) {
	if (!mac_cache[i].valid) {  // Check for the first unused spot
	    mac_cache[i].ip_addr = ip_addr;
	    memcpy(mac_cache[i].mac, mac, sizeof(mac_cache[i].mac));
	    mac_cache[i].valid = 1;
	    return;
	}
    }
}

static int get_mac_address(const char *ifname, struct sockaddr_in addr, uint8_t *mac) {
    if (get_mac_from_cache(addr.sin_addr, mac)) {
	return 0; // MAC found in cache, return immediately
    }

    struct arpreq arp_req;
    int sock_fd;
    memset(&arp_req, 0, sizeof(struct arpreq));
    struct sockaddr_in *sin = (struct sockaddr_in *)&arp_req.arp_pa;
    sin->sin_family = AF_INET;
    sin->sin_addr = addr.sin_addr;

    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	perror("socket failed");
	zlog_error(zlog_server, "socket creation failed: %s", strerror(errno));
	return -1;
    }

    strncpy(arp_req.arp_dev, ifname, IFNAMSIZ-1);
    if (ioctl(sock_fd, SIOCGARP, &arp_req) == -1) {
	zlog_error(zlog_server, "ioctl SIOCGARP failed: %s", strerror(errno));
	close(sock_fd);
	return -1;
    }

    memcpy(mac, arp_req.arp_ha.sa_data, sizeof(uint8_t) * 6);
    add_mac_to_cache(addr.sin_addr, mac); // Add to cache

    close(sock_fd);
    return 0;
}

void set_socket_non_blocking(int socket_fd)
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

void handle_new_connection(int epoll_fd, const char *ifname, int server_fd, int thread_id)
{
	pid_t tid = gettid();

	int new_socket, ret;
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);

	// Accept a new client connection
	new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
	if (new_socket == -1) {
		zlog_error(zlog_server, "Fail to accept new client connection: %s", strerror(errno));
		return;
	}

	//ret = setsockopt(new_socket, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int));
	//assert(ret == 0);

	char *ip_addr_str = inet_ntoa(client_addr.sin_addr);

	zlog_info(zlog_server, "Accepted connection (%d) from %s:%d", new_socket, ip_addr_str, ntohs(client_addr.sin_port));

	// Add the new client socket to the epoll event list

	struct epoll_event event;
	event.events = EPOLLIN | EPOLLRDHUP;
	struct http_client *client = create_http_client(epoll_fd, new_socket);
	client->epoll_data_u32 = S3_HTTP_EVENT;

	// TODO: optimize
	ret = get_mac_address(ifname, client_addr, client->client_mac);
	assert(ret == 0);

	//printf("MAC addr of remote ip %s is ", ip_addr_str);
	//print_mac_address(client->client_mac);

	client->client_addr = client_addr.sin_addr.s_addr;
	client->client_port = client_addr.sin_port;

	event.data.ptr = client;

	set_socket_non_blocking(new_socket);

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, new_socket, &event) == -1) {
		zlog_error(zlog_server, "Fail to add new client conn to epoll: %s", strerror(errno));
		close(new_socket);
		free_http_client(client);
	}
}

void handle_client_disconnect(int epoll_fd, struct http_client *client,
	int thread_id, struct handoff_out *handoff_out_ctxs)
{
	int fd = client->fd;
	int ret = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
	assert(ret == 0);

	zlog_info(zlog_server, "Thread %d client disconnected %d", thread_id, fd);

#ifdef USE_MIGRATION
	// we don't free up client since we still need it for handoff_reset
	if (client->from_migrate != -1) {
		zlog_debug(zlog_handoff, "HANDOFF_OUT Create handoff reset client to osd %d on conn %d", client->from_migrate, client->fd);
		handoff_out_serialize_reset(client);
		int osd_arr_index = get_arr_index_from_osd_id(client->from_migrate);
		handoff_out_issue_urgent(epoll_fd, HANDOFF_OUT_EVENT, client,
			&handoff_out_ctxs[osd_arr_index], osd_arr_index, thread_id);
		return;
	}
#endif

	close(fd);
	tls_free_client(client);
	free_http_client(client);
}

static void do_llhttp_execute(struct http_client *client, char *client_data_buffer, ssize_t bytes_received)
{
	enum llhttp_errno ret;

	// Echo the received data back to the client
	ret = llhttp_execute(&(client->parser), client_data_buffer, bytes_received);
	if (ret != HPE_OK) {
		zlog_error(zlog_server, "Parse error: %s %s", llhttp_errno_name(ret), client->parser.reason);
		zlog_error(zlog_server, "buf: %s", client_data_buffer);
		zlog_error(zlog_server, "Error pos: %ld %ld %p %p", bytes_received, llhttp_get_error_pos(&(client->parser)) - client_data_buffer, client_data_buffer, llhttp_get_error_pos(&(client->parser)));
		//handle_client_disconnect(epoll_fd, client); // Handle client disconnection
		exit(1);
		//close(client->fd);
		//free_http_client(client);
	}
}

// return number of bytes left in client_data_buffer after this function
// on error return -1
static ssize_t handle_client_data_ssl(struct http_client *client, SSL_CTX *ssl_ctx,
	char *client_data_buffer, ssize_t bytes_received)
{
	// printf("%s: bytes_received %d\n", __func__, bytes_received);

	// HTTP or HTTPS not decided and SSL not initlized for this conn
	if (client->tls.ssl == NULL) {
		if (tls_init_client(ssl_ctx, client, client_data_buffer, bytes_received) == -1) {
			perror("tls_conn_init");
			return -1;
		}

		// Not enough bytes to identity HTTP or HTTPS
		if (client->tls.is_ssl && client->tls.ssl == NULL) {
			return 0;
		}

		// Not SSL, use HTTP, need to feed bytes to llhttp from preivous recv first
		if (!client->tls.is_ssl) {
			if (client->tls.client_hello_check_off > 0) {
				do_llhttp_execute(client, (char *)client->tls.client_hello_check_buf,
					client->tls.client_hello_check_off);
			}
			return bytes_received;
		}
	}

	if (client->tls.is_ktls_set) {
		// do nothing
		return bytes_received;
	}

	if (!client->tls.is_handshake_done) {
		return tls_handle_handshake(client, client_data_buffer, bytes_received);
	}

	zlog_error(zlog_tls, "Error state as handshake is done but ktls not set");
	return -1; // Shouldn't happen
	// Handle handshake?
}

int handle_client_data(int epoll_fd, struct http_client *client,
	char *client_data_buffer, int thread_id, rados_ioctx_t bucket_io_ctx,
	rados_ioctx_t data_io_ctx, SSL_CTX *ssl_ctx)
{
	ssize_t bytes_received;

	memset(client_data_buffer, 0, BUF_SIZE);
	bytes_received = recv(client->fd, client_data_buffer, BUF_SIZE, 0);
	if (bytes_received <= 0) {
		// Client closed the connection or an error occurred
		if (bytes_received == 0) {
			zlog_debug(zlog_server, "conn %d recv returned 0", client->fd);
		} else if (errno == EAGAIN && client->tls.is_ssl && client->tls.is_ktls_set) {
			zlog_debug(zlog_server, "recv returned EAGAIN (client->tls.ssl %p)", client->tls.ssl);
			return 0;
		} else {
			zlog_debug(zlog_server, "conn %d recv returned -1 (%s)", client->fd, strerror(errno));
		}

		// Remove the client socket from the epoll event list
		return -1;
	}

	if (client->tls.is_ssl){
		bytes_received = handle_client_data_ssl(client, ssl_ctx, client_data_buffer, bytes_received);
		if (bytes_received == -1) {
			zlog_fatal(zlog_server, "handle_client_data_ssl returned %ld", bytes_received);
			//exit(EXIT_FAILURE);
			return -1;
		}
		if (bytes_received == 0) return 0;
	}

	client->bucket_io_ctx = bucket_io_ctx;
	client->data_io_ctx = data_io_ctx;
	do_llhttp_execute(client, client_data_buffer, bytes_received);

	return 0;
}

static void *conn_wait(void *arg)
{
	// we also need a dummy handoff_in_ctx for listenfd
	int handoff_in_listenfd = -1;

	struct handoff_in handoff_in_ctxs[num_osds];
	struct handoff_out handoff_out_ctxs[num_peers];
	memset(handoff_in_ctxs, 0, sizeof(handoff_in_ctxs));
	memset(handoff_out_ctxs, 0, sizeof(handoff_out_ctxs));

	rados_ioctx_t bucket_io_ctx;
	rados_ioctx_t data_io_ctx;

	struct thread_param *param = (struct thread_param*)arg;
	int server_fd = -1;
	int thread_id = param->thread_id;
	rados_t cluster; // = param->cluster;

	//char client_data_buffer[BUF_SIZE];
	char *client_data_buffer = malloc(BUF_SIZE);

	int ret;
	int epoll_fd, event_count;
	struct epoll_event event;
	struct epoll_event events[MAX_EVENTS];

	SSL_CTX *ssl_ctx = tls_init_ctx("./assets/server.crt", "./assets/server.key");
	if (ssl_ctx == NULL) {
		zlog_fatal(zlog_tls, "tls_init_ctx failed");
		exit(EXIT_FAILURE);
	}

	int err = 0;
	err = rados_create2(&cluster, "ceph", "client.admin", 0);
	if (err < 0) {
		zlog_fatal(zlog_object_store, "cannot create a cluster handle: %s", strerror(-err));
		exit(1);
	}

	err = rados_conf_read_file(cluster, "/etc/ceph/ceph.conf");
	if (err < 0) {
		zlog_fatal(zlog_object_store, "cannot read config file");
		exit(1);
	}

	err = rados_connect(cluster);
	if (err < 0) {
		zlog_fatal(zlog_object_store, "cannot connect to cluster");
		exit(EXIT_FAILURE);
	}

	err = rados_ioctx_create(cluster, BUCKET_POOL, &bucket_io_ctx);
	if (err < 0) {
		zlog_fatal(zlog_object_store, "cannot open rados pool %s", BUCKET_POOL);
		rados_shutdown(cluster);
		exit(1);
	}

	err = rados_ioctx_create(cluster, DATA_POOL, &data_io_ctx);
	if (err < 0) {
		zlog_fatal(zlog_object_store, "cannot open rados pool %s", DATA_POOL);
		rados_shutdown(cluster);
		exit(1);
	}

	// Create an epoll instance
	if ((epoll_fd = epoll_create1(0)) == -1) {
		zlog_fatal(zlog_server, "epoll_create1(0) failed: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

#ifdef USE_MIGRATION
	if (enable_migration) {
		// Add handoff_in read_domain_socket into epoll
		handoff_in_listenfd = handoff_in_listen(param->thread_id);
		if (handoff_in_listenfd == -1) {
			zlog_fatal(zlog_handoff, "handoff_in_listen failed: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}
		memset(&event, 0 , sizeof(event));
		handoff_in_ctxs[num_osds - 1].epoll_data_u32 = HANDOFF_IN_EVENT;
		handoff_in_ctxs[num_osds - 1].epoll_fd = epoll_fd;
		handoff_in_ctxs[num_osds - 1].fd = handoff_in_listenfd;
		event.events = EPOLLIN;
		event.data.ptr = &handoff_in_ctxs[num_osds - 1];
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, handoff_in_listenfd, &event) == -1) {
			zlog_fatal(zlog_handoff, "Register epoll for handoff_in_listenfd %d failed: %s", handoff_in_listenfd, strerror(errno));
			exit(EXIT_FAILURE);
		}
		for (int i = 0; i < num_peers; i++)
		{
			handoff_in_ctxs[i].thread_id = param->thread_id;
			handoff_in_ctxs[i].osd_arr_index = i;
			handoff_out_ctxs[i].thread_id = param->thread_id;
			handoff_out_ctxs[i].osd_arr_index = i;
		}
	}
#endif

	// Create a TCP socket
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		zlog_fatal(zlog_server, "Create server_fd failed: %s", strerror(errno)),
		exit(EXIT_FAILURE);
	}

	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,  &(int){1}, sizeof(int)) < 0)
		perror("setsockopt(SO_REUSEADDR) failed");

	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int)) < 0)
		perror("setsockopt(SO_REUSEPORT) failed");

	// Initialize server address structure
	struct sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(S3_HTTP_PORT);

	// Bind the socket to the server address
	if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	// Listen for incoming connections
	if (listen(server_fd, SOMAXCONN) == -1) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	// Add the server socket to the epoll event list
	memset(&event, 0 , sizeof(event));
	event.events = EPOLLIN;
	struct http_client *server_client = create_http_client(epoll_fd, server_fd);
	server_client->epoll_data_u32 = S3_HTTP_EVENT;
	event.data.ptr = server_client;
	ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event);
	assert(ret == 0);

#ifdef USE_MIGRATION
	if (enable_migration)
		zlog_debug(zlog_handoff, "HANDOFF_IN Ready to accept incoming handoff (fd=%d,port=%d)", handoff_in_listenfd, HANDOFF_CTRL_PORT + param->thread_id);
#endif
	zlog_debug(zlog_server, "S3_HTTP Ready to accept HTTP(S) connections (fd=%d,port=%d)", server_fd, S3_HTTP_PORT);

	while (server_running) {
		// Wait for events using epoll
		memset(events, 0, sizeof(struct epoll_event) * MAX_EVENTS);
		event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
		if (event_count == -1) {
			if (errno == EINTR) {
				//printf("EINTR\n");
				continue;
			}
			else {
				zlog_fatal(zlog_server, "epoll_wait failed: %s", strerror(errno));
				exit(EXIT_FAILURE);
			}
		}

		for (int i = 0; i < event_count; i++) {
			uint32_t epoll_data_u32 = *((uint32_t*)events[i].data.ptr);
			if (epoll_data_u32 == S3_HTTP_EVENT) {
				// Handle events using callback functions
				struct http_client *c = (struct http_client *)events[i].data.ptr;
				if (c->fd == server_fd) {
					handle_new_connection(epoll_fd, param->ifname, server_fd, thread_id);
					zlog_debug(zlog_server, "S3_HTTP Accepted new connction");
				} else if ((events[i].events & EPOLLERR) ||
						   (events[i].events & EPOLLHUP) ||
						   (events[i].events & EPOLLRDHUP)) {
					zlog_error(zlog_server, "S3_HTTP error event (fd=%d,events=%d,object_name=%s,port=%d)", c->fd, events[i].events, c->object_name, ntohs(c->client_port));
					fflush(stdout);
					//exit(1);
					handle_client_disconnect(epoll_fd, c, param->thread_id, handoff_out_ctxs);
				} else if (events[i].events & EPOLLOUT) {
					ret = send_client_data(c);
					zlog_debug(zlog_server, "S3_HTTP_EVENT send_client_data (fd=%d,events=%d,object_name=%s,port=%d)", c->fd, events[i].events, c->object_name, ntohs(c->client_port));
					if (ret == -1) {
						zlog_debug(zlog_server, "S3_HTTP_EVENT client disconnected after send_client_data (fd=%d)", c->fd);
						handle_client_disconnect(epoll_fd, c, param->thread_id, handoff_out_ctxs);
					}
				} else if (events[i].events & EPOLLIN) {
					zlog_debug(zlog_server, "S3_HTTP_EVENT handle_client_data");
					ret = handle_client_data(epoll_fd, c, client_data_buffer, thread_id, bucket_io_ctx, data_io_ctx, ssl_ctx);
					if (ret == -1) {
						zlog_debug(zlog_server, "S3_HTTP_EVENT client disconnected after send_client_disconnect (fd=%d)", c->fd);
						handle_client_disconnect(epoll_fd, c, param->thread_id, handoff_out_ctxs);
					}
#ifdef USE_MIGRATION
					// check if ret okay, connection could be closed
					if (ret != -1 && enable_migration && c->to_migrate != -1) {
						zlog_debug(zlog_handoff, "S3_HTTP_EVENT To migrate conn (fd=%d,OSD=%d)", c->fd, c->to_migrate);
						handoff_out_serialize(c);
						zlog_debug(zlog_handoff, "HANDOFF_OUT Serialized client (fd=%d)", c->fd);
						int osd_arr_index = get_arr_index_from_osd_id(c->to_migrate);
						handoff_out_issue(epoll_fd, HANDOFF_OUT_EVENT, c, &handoff_out_ctxs[osd_arr_index], osd_arr_index, param->thread_id);
						zlog_debug(zlog_handoff, "HANDOFF_OUT Issued for client (fd=%d)", c->fd);
					}
#endif
				}
				else {
					zlog_error(zlog_server, "S3_HTTP unhandled event (fd %d events %d)", c->fd, events[i].events);
				}
			}
#ifdef USE_MIGRATION
			else if (enable_migration && epoll_data_u32 == HANDOFF_IN_EVENT) {
				struct handoff_in *in_ctx = (struct handoff_in *)events[i].data.ptr;
				in_ctx->data_io_ctx = data_io_ctx;
				in_ctx->bucket_io_ctx = bucket_io_ctx;
				if (in_ctx->fd == handoff_in_listenfd) {
					zlog_debug(zlog_handoff, "HANDOFF_IN_EVENT Receiving incoming handoff event");
					if (events[i].events & EPOLLIN) {
						struct sockaddr_in in_addr;
						socklen_t in_len = sizeof(in_addr);
						int in_fd = accept(handoff_in_listenfd, (struct sockaddr *)&in_addr, &in_len);
						if (in_fd == -1) {
							zlog_error(zlog_handoff, "Fail to accept handoff_in_listenfd %d: %s", handoff_in_listenfd, strerror(errno));
							break;
						}

						if (setsockopt(in_fd, IPPROTO_TCP, TCP_QUICKACK, &(int){1}, sizeof(int)) == -1) {
							zlog_fatal(zlog_handoff, "Fail to set TCP_QUICKACK on in_fd %d: %s", in_fd, strerror(errno));
							exit(EXIT_FAILURE);
						}

						if (setsockopt(in_fd, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) == -1) {
							zlog_fatal(zlog_handoff, "Fail to set TCP_NODELAY on in_fd %d: %s", in_fd, strerror(errno));
							exit(EXIT_FAILURE);
						}

						int osd_arr_index = 0;
						for (; osd_arr_index < num_peers; osd_arr_index++) {
							if (osd_addrs[osd_arr_index].sin_addr.s_addr == in_addr.sin_addr.s_addr) {
								break;
							}
						}

						if (osd_arr_index < num_peers) {
							zlog_info(zlog_handoff, "HANDOFF_IN_EVENT Accepted handoff_in (in_fd=%d,host=%s:%d,osd=%d)", in_fd, osd_addr_strs[i], ntohs(in_addr.sin_port), osd_ids[i]);
						}
						else {
							zlog_fatal(zlog_handoff, "HANDOFF_IN_EVENT Unkown handoff_in client %s, not in osd list, drop", inet_ntoa(in_addr.sin_addr));
							close(in_fd);
							exit(EXIT_FAILURE);
						}

						set_socket_non_blocking(in_fd);

						if (handoff_in_ctxs[osd_arr_index].fd != 0) {
							// main thread will close old fd and cause global epoll list delete
							zlog_debug(zlog_handoff, "HANDOFF_IN Received a new conn fd=%d and overwrites old conn (in_fd=%d,osd=%d)",
								in_fd, handoff_in_ctxs[osd_arr_index].fd, osd_ids[osd_arr_index]);
							close(handoff_in_ctxs[osd_arr_index].fd);
						}

						handoff_in_ctxs[osd_arr_index].fd = in_fd;
						handoff_in_ctxs[osd_arr_index].epoll_fd = epoll_fd;
						handoff_in_ctxs[osd_arr_index].epoll_data_u32 = HANDOFF_IN_EVENT;
						memset(&event, 0 , sizeof(event));
						event.events = EPOLLIN | EPOLLRDHUP;
						// maybe a reconnect socket when still have buf not
						// sent out, need to set epoll as OUT mode
						if (handoff_in_ctxs[osd_arr_index].send_protobuf != NULL) {
							event.events = EPOLLOUT | EPOLLRDHUP;
						}
						event.data.ptr = &handoff_in_ctxs[osd_arr_index];
						ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, in_fd, &event);
						assert(ret == 0);
					} else {
						zlog_error(zlog_handoff, "HANDOFF_IN Unhandled event on (handoff_in_listenfd=%d,events=%d)", handoff_in_listenfd, events[i].events);
					}
				} else if ((events[i].events & EPOLLERR) ||
						   (events[i].events & EPOLLHUP) ||
						   (events[i].events & EPOLLRDHUP)){
					zlog_error(zlog_handoff, "HANDOFF_IN received err/hup event, closing (fd=%d,events=%d,osd=%d)", in_ctx->fd, events[i].events, osd_ids[in_ctx->osd_arr_index]);
					handoff_in_disconnect(in_ctx);
				} else if (events[i].events & EPOLLIN) {
					zlog_debug(zlog_handoff, "HANDOFF_IN_EVENT handoff_in_recv");
					bool ready_to_send = false;
					struct http_client *client_to_handoff_again = NULL;
					handoff_in_recv(in_ctx, &ready_to_send, &client_to_handoff_again);
					if (ready_to_send) {
						zlog_debug(zlog_handoff, "HANDOFF_IN_EVENT handoff_in_recv ready to send");
						handoff_in_send(in_ctx);
					}
					if (client_to_handoff_again) {
						zlog_debug(zlog_handoff, "HANDOFF_IN TO re-handoff to (fd=%d,osd=%d)", client_to_handoff_again->fd, client_to_handoff_again->to_migrate);
						int osd_arr_index = get_arr_index_from_osd_id(client_to_handoff_again->to_migrate);
						handoff_out_issue_urgent(epoll_fd, HANDOFF_OUT_EVENT, client_to_handoff_again,
							&handoff_out_ctxs[osd_arr_index], osd_arr_index, param->thread_id);
					}
				} else if (events[i].events & EPOLLOUT) {
					zlog_debug(zlog_handoff, "HANDOFF_IN_EVENT handoff_in_send");
					handoff_in_send(in_ctx);
				}
				else {
					zlog_error(zlog_handoff, "HANDOFF_IN Unhandled event (in_ctx->fd=%d,events=%d)", in_ctx->fd, events[i].events);
				}
			} else if (enable_migration && epoll_data_u32 == HANDOFF_OUT_EVENT) {
				struct handoff_out *out_ctx = (struct handoff_out *)events[i].data.ptr;
				if ((events[i].events & EPOLLERR) ||
					(events[i].events & EPOLLHUP) ||
					(events[i].events & EPOLLRDHUP)) {
					zlog_error(zlog_handoff, "HANDOFF_OUT_EVENT handoff_out_reconnect");
					// means current connection is broken
					handoff_out_reconnect(out_ctx);
				} else if (events[i].events & EPOLLOUT) {
					zlog_debug(zlog_handoff, "HANDOFF_OUT_EVENT handoff_out_send (out_ctx->fd=%d)", out_ctx->fd);
					if (out_ctx->is_fd_connected) {
						handoff_out_send(out_ctx);
					} else {
						handoff_out_reconnect(out_ctx);
					}
				} else if (events[i].events & EPOLLIN) {
					zlog_debug(zlog_handoff, "HANDOFF_OUT_EVENT handoff_out_recv (out_ctx->fd=%d,fd=%d)", out_ctx->fd, out_ctx->client->fd);
					// handle handoff response, if all received, then swtich back to epollout
					handoff_out_recv(out_ctx);
				}
				else {
					zlog_error(zlog_handoff, "HANDOFF_OUT Unhandled event (out_ctx->fd=%d,events=%d)", events[i].data.fd, events[i].events);
				}
			}
#endif
			else {
				zlog_error(zlog_server, "Unhandled event (events=%d,data.u32=%d)", events[i].events, epoll_data_u32);
			}
		}
	}


#ifdef USE_MIGRATION
	if (enable_migration) {
		close(handoff_in_listenfd);
		// TODO: close all handoff_out sockets
		// TODO: close all pending buffer
	}
#endif

	rados_shutdown(cluster);
	close(server_fd);
	close(epoll_fd);


	tls_uninit_ctx(ssl_ctx);
	free_http_client(server_client);

	rados_ioctx_destroy(bucket_io_ctx);
	rados_ioctx_destroy(data_io_ctx);

	free(client_data_buffer);

	return NULL;
}

static int rearrange_osd_addrs(const char *ifname)
{
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, ifname , IFNAMSIZ);

	if (ioctl(fd, SIOCGIFADDR, &ifr) == -1 ) {
		zlog_fatal(zlog_server, "IOCTL SIOCGIFADDR failed");
		close(fd);
		exit(EXIT_FAILURE);
	}

	char *my_ip_address = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

	// Perform the IOCTL operation to fetch the hardware address
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
		zlog_fatal(zlog_server, "IOCTL SIOCGIFHWADDR failed");
		close(fd);
		exit(EXIT_FAILURE);
	}

	memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);

	close(fd);

	// put osd info of this node to end of array
	for (int i = 0; i < num_osds; i++) {
		if (strcmp(osd_addr_strs[i], my_ip_address) == 0) {
			char *osd_addr_str_tmp = osd_addr_strs[num_osds - 1];
			osd_addr_strs[num_osds - 1] = osd_addr_strs[i];
			osd_addr_strs[i] = osd_addr_str_tmp;

			int osd_id_tmp = osd_ids[num_osds - 1];
			osd_ids[num_osds - 1] = osd_ids[i];
			osd_ids[i] = osd_id_tmp;
		}
	}

	char mac_str[18];
	sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
		my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
	// current xo-server node is not an OSD
	if (strcmp(osd_addr_strs[num_osds - 1], my_ip_address) != 0) {
		osd_addr_strs[num_osds] = strdup(my_ip_address);
		osd_ids[num_osds] = -1;
		num_osds++;
		zlog_info(zlog_server, "xo-server is not running on an OSD (interface %s, ip %s, mac %s)",
			ifname, osd_addr_strs[num_osds - 1], mac_str);
	} else {
		zlog_info(zlog_server, "xo-server is running on an OSD (interface %s, ip %s, mac %s, osd_id %d)",
			ifname, osd_addr_strs[num_osds - 1], mac_str, osd_ids[num_osds - 1]);
	}

	for (int i = 0; i < num_osds; i++)
	{
		memset(&osd_addrs[i], 0, sizeof(osd_addrs[i]));
		osd_addrs[i].sin_family = AF_INET;
		osd_addrs[i].sin_port = htons(HANDOFF_CTRL_PORT);
		if (inet_pton(AF_INET, osd_addr_strs[i], &osd_addrs[i].sin_addr) <= 0) {
			zlog_fatal(zlog_server, "Invalid address \"%s\" for osd id %d", osd_addr_strs[i], osd_ids[i]);
			exit(EXIT_FAILURE);
		}
	}

	num_peers = num_osds - 1;
	return 0;
}

static int ceph_config_parser(void* user, const char* section, const char* name, const char* value)
{
	long osd_id = -1;
	if (strncmp(section, "osd", 3) == 0) {
		char *id = strstr(section, ".");
		if (id != NULL) {
			osd_id = atol(id+1);
			if (strcmp(name, "public_addr") == 0) {
				osd_addr_strs[num_osds] = strdup(value);
				osd_ids[num_osds] = osd_id;
				num_osds++;
			}
			if (num_osds == MAX_OSDS) {
				zlog_fatal(zlog_server, "num_osds %d exceeding MAX_OSDS %d", num_osds, MAX_OSDS);
				exit(EXIT_FAILURE);
			}
		}
	}

	return 1;
}

int main(int argc, char *argv[])
{
	struct sigaction sa;
	int err;

	err = zlog_init("/etc/zlog.conf");
	if (err) {
		printf("init failed\n");
		return -1;
	}

	zlog_handoff = zlog_get_category("handoff");
	if (!zlog_handoff) {
		printf("get handoff zlog fail\n");
		zlog_fini();
		return -2;
	}

	zlog_queue = zlog_get_category("queue");
	if (!zlog_queue) {
		printf("get queue zlog fail\n");
		zlog_fini();
		return -2;
	}


	zlog_server = zlog_get_category("server");
	if (!zlog_server) {
		printf("get server zlog fail\n");
		zlog_fini();
		return -2;
	}

	zlog_tls = zlog_get_category("tls");
	if (!zlog_tls) {
		printf("get tls zlog fail\n");
		zlog_fini();
		return -2;
	}

	zlog_object_store = zlog_get_category("object_store");
	if (!zlog_object_store) {
		printf("get tls zlog fail\n");
		zlog_fini();
		return -2;
	}
//	struct handoff_in in_ctx;
//	FILE *f = fopen("sock_ulp.proto", "rb");
//	in_ctx.recv_protobuf = malloc(237);
//	fread(in_ctx.recv_protobuf, 237, 1, f);
//	fclose(f);
//	SocketSerialize *migration_info = socket_serialize__unpack(NULL, 237, in_ctx.recv_protobuf);
//	handoff_in_deserialize(&in_ctx, migration_info);

	signal(SIGPIPE, SIG_IGN);

#if USE_MIGRATION
	if (argc != 7) {
		fprintf(stderr, "Usage: %s [interface] [threads] [enable migration (0/1)] [use TC] [TC offload] [use hybrid if TC offload = 1]\n", argv[0]);
#else
	if (argc != 3) {
		fprintf(stderr, "Usage: %s [interface] [threads]\n", argv[0]);
#endif
		exit(1);
	}

#if USE_MIGRATION
	if (atoi(argv[3]) == 1)
		enable_migration = true;
	else
		enable_migration = false;

	// initialize libforward-tc
	if (enable_migration) {
		err = init_forward(argv[1], "ingress", "1:");
		assert(err >= 0);
	}

	if (atoi(argv[4]) == 1)
		use_tc = true;
	else
		use_tc = false;

	if (atoi(argv[5]) == 1)
		tc_offload = true;
	else
		tc_offload = false;

	if (atoi(argv[6]) == 1)
		tc_hybrid = true;
	else
		tc_hybrid = false;

#ifdef ASYNC_WRITE
	zlog_info(zlog_server, "RADO Async Write: enabled");
#else
	zlog_info(zlog_server, "RADO Async Write: disabled");
#endif
#ifdef ASYNC_READ
	zlog_info(zlog_server, "RADO Async Read: enabled");
#else
	zlog_info(zlog_server, "RADO Async Read: disabled");
#endif
	zlog_info(zlog_server, "Connection migration: %s", enable_migration ? "enabled" : "disabled");
	if (enable_migration)
		zlog_info(zlog_server, "Use TC: %s (%s offload) %s eBPF hybrid", use_tc ? "yes" : "no", tc_offload ? "with" : "without", tc_hybrid ? "with" : "without");
#endif
	err = tls_init();
	if (err < 0) {
		zlog_fatal(zlog_tls, "cannot init openssl");
		exit(1);
	}

	long max_cores = sysconf(_SC_NPROCESSORS_ONLN);
	long nproc = atol(argv[2]);
	pthread_t threads[nproc];
	struct thread_param param[nproc];

	// get my IP address and mapping OSDs
	char *ifname = argv[1];
	err = ini_parse("/etc/ceph/ceph.conf", ceph_config_parser, NULL);
	if (err < 0) {
		zlog_fatal(zlog_object_store, "Can't read '%s'!", "/etc/ceph/ceph.conf");
		exit(1);
	}
	else if (err) {
		zlog_fatal(zlog_object_store, "Bad config file (first error on line %d)!", err);
		exit(1);
	}

	err = rearrange_osd_addrs(ifname);
	assert(err == 0);

	cpu_set_t cpus;
	pthread_attr_t attr;
	sigset_t sigmask;

	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGINT);
	sigaddset(&sigmask, SIGPIPE);

	pthread_attr_init(&attr);

	sa.sa_handler = handleCtrlC;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);

	CPU_ZERO(&cpus);
	CPU_SET(0, &cpus);
	pthread_t current_thread = pthread_self();
	//pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpus);

#ifdef USE_MIGRATION
	pthread_t rule_consumer;

	if (use_tc && tc_hybrid) {
		/* initialize rule queue */
		int rc;
		q = malloc(sizeof(rule_queue_t));
		if (!q)
		{
			zlog_error(zlog_queue, "Failed to allocate memory for rule queue");
			exit(EXIT_FAILURE);
		}
		rule_queue_init(q, Q_SIZE);

		/* set cpu for the consumer thread */
		CPU_ZERO(&cpus);
		CPU_SET(max_cores - 1, &cpus);

		/* create the consumer thread */
		rc = pthread_attr_setsigmask_np(&attr, &sigmask);
		assert(rc == 0);
		//rc = pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpus);
		//assert(rc == 0);
		rc = pthread_create(&rule_consumer, &attr, &rule_q_consumer, q);
		assert(rc == 0);
		rc = pthread_detach(rule_consumer);
		assert(rc == 0);
	}
#endif

	zlog_info(zlog_server, "Launching %ld threads", nproc);
	for (int i = 0; i < nproc; i++) {
		param[i].thread_id = i;
		//param[i].cluster = cluster;
		strncpy(param[i].ifname, ifname, 32);

		CPU_ZERO(&cpus);
		CPU_SET((i + (max_cores)) % (max_cores), &cpus);

		pthread_attr_setsigmask_np(&attr, &sigmask);
		//pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpus);

		if (pthread_create(&threads[i], &attr, &conn_wait, &param[i]) != 0) {
			zlog_fatal(zlog_server, "fail to create thread %d", i);
			exit(1);
		}
	}

	pause();
	zlog_info(zlog_server, "terminating");

	for (int i = 0; i < nproc; i++) {
		if (pthread_kill(threads[i], SIGUSR1) != 0) {
			zlog_fatal(zlog_server, "fail to signal thread %d", i);
			exit(1);
		}

		if (pthread_join(threads[i], NULL) != 0) {
			zlog_fatal(zlog_server, "fail to join thread %d", i);
			exit(1);
		}
	}

#ifdef USE_MIGRATION
//	if (use_tc && tc_hybrid) {
//		rule_queue_destroy(q);
//	}
#endif
	pthread_attr_destroy(&attr);

	for (int i = 0; i < num_osds; i++) {
		if (osd_addr_strs[i] != NULL) free(osd_addr_strs[i]);
	}

#ifdef USE_MIGRATION
	if (enable_migration) {
		fini_forward();
		fini_forward_ebpf();
	}
#endif
	zlog_info(zlog_server, "%s terminated", argv[0]);
	zlog_fini();

	return 0;
}
