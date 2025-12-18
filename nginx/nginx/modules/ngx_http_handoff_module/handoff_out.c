#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>

#include "ngx_http_handoff_module.h"
#include "handoff_out.h"
#include "connect.h"
#include "util.h"

static void handoff_out_read_handler(ngx_event_t *ev) {
    int rc = -1;
    ngx_connection_t *c = ev->data;
    //ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0, "upstream sock read event fd=%d", c->fd);

    //printf("handoff_out_read_handler: fd=%d\n", c->fd);
    rc = c->recv(c, c->recv_buffer, ev->available);
    if (rc == NGX_EAGAIN) {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0, "upstream sock read event fd=%d socket not ready", c->fd);
        //rc = ngx_add_event(ev, NGX_READ_EVENT, NGX_LEVEL_EVENT); 
        //assert(rc == 0);
    }
    else {
        if (rc == NGX_ERROR || ev->pending_eof || ev->eof) {
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0, "upstream sock read event fd=%d error %s, exiting", c->fd, strerror(ngx_errno));
            rc = ngx_del_event(ev, NGX_READ_EVENT, NGX_CLEAR_EVENT); 
            free(c->recv_buffer);
            c->recv_buffer = NULL;
            ngx_close_connection(c);
            return;
        }

        // look for done done
        char *ptr0 = strstr((char*)c->recv_buffer, "DONEDONE");
        if (ptr0) {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "backend acknowledged");
            // backend acknowledged, close this connection
            rc = ngx_del_event(ev, NGX_READ_EVENT, NGX_CLEAR_EVENT); 
            free(c->recv_buffer);
            c->recv_buffer = NULL;
            ngx_http_close_connection(c);
            return;
        }

        //ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0, "upstream sock read event fd=%d received=%d: %s", c->fd, rc, c->recv_buffer);

        // apply redirection
        struct handoff_out *handoff_out_ctx = c->handoff_out_ctx;
        ngx_http_handoff_main_conf_t *my_conf = handoff_out_ctx->ngx_conf;

        char *ptr5;
        ptr5 = strstr((char*)c->recv_buffer, "\r\n\r\n") + 4;

        char *content_len_str = strstr((char*)c->recv_buffer, "Content-Length: ") + strlen("Content-Length: ");
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0, "http line %s", content_len_str);
        handoff_out_ctx->recv_protobuf_received = atoi(content_len_str);
        handoff_out_ctx->recv_protobuf_len = handoff_out_ctx->recv_protobuf_received;

        //ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0, "content length line: %s", buf);
        //ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, " resp protobuf %s", ptr5+sizeof(uint32_t));

        SocketSerialize *migration_info = socket_serialize__unpack(NULL, handoff_out_ctx->recv_protobuf_len-sizeof(uint32_t), (uint8_t*)ptr5+sizeof(uint32_t));
        if (migration_info == NULL) {
                ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0, "unable to unpack protobuf len=%d %s", handoff_out_ctx->recv_protobuf_len-sizeof(uint32_t), ptr5+sizeof(uint32_t));
                exit(EXIT_FAILURE);
        }
        if (migration_info->msg_type != HANDOFF_DONE) {
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "HANDOFF_OUT Received migration respond not HANDOFF_DONE");
                exit(EXIT_FAILURE);
        }

        if (handoff_out_ctx->client->from_migrate == -1) {
            // normal handoff, insert redirection rule
            uint8_t fake_server_mac[6];
            memcpy(fake_server_mac, &(migration_info->peer_mac), sizeof(uint8_t) * 6);
     
ngx_log_debug4(NGX_LOG_DEBUG_EVENT, ev->log, 0, "apply ip redir (%lu:%u , %lu:%u)\n", migration_info->peer_addr, ntohs(migration_info->peer_port), migration_info->self_addr, ntohs(migration_info->self_port) - 1 - 1);
//printf("apply ip redir (%lu:%u , %lu:%u)\n", migration_info->peer_addr, ntohs(migration_info->peer_port), migration_info->self_addr, ntohs(migration_info->self_port) - 1 - 1);
            rc = apply_redirection_ebpf(migration_info->peer_addr, migration_info->self_addr,
                                        migration_info->peer_port, htons(ntohs(migration_info->self_port) - 1 - 1),
                                        migration_info->peer_addr, my_conf->my_mac, my_conf->peer_sockaddr[handoff_out_ctx->client->to_migrate].sin_addr.s_addr, fake_server_mac,
                                        migration_info->peer_port, migration_info->self_port, false);
            assert(rc == 0);
            //rc = remove_redirection_ebpf(migration_info->peer_addr, migration_info->self_addr,
            //                             migration_info->peer_port, htons(ntohs(migration_info->self_port) - 1 - 1));
            //assert(rc == 0);
        }
        else {
            // handoff back, remove src IP modification
ngx_log_debug4(NGX_LOG_DEBUG_EVENT, ev->log, 0, "remove src ip redir (%lu:%u , %lu:%u)\n", migration_info->self_addr, ntohs(migration_info->self_port), migration_info->peer_addr, ntohs(migration_info->peer_port));
//printf("remove src ip redir (%lu:%u , %lu:%u)\n", migration_info->self_addr, ntohs(migration_info->self_port), migration_info->peer_addr, ntohs(migration_info->peer_port));
            rc = remove_redirection_ebpf(migration_info->self_addr, migration_info->peer_addr,
                                         migration_info->self_port, migration_info->peer_port);
            assert(rc == 0);
ngx_log_debug4(NGX_LOG_DEBUG_EVENT, ev->log, 0, "remove blocking ip (%lu:%u , %lu:%u)\n", migration_info->peer_addr, ntohs(migration_info->peer_port), migration_info->self_addr, ntohs(migration_info->self_port));
//printf("remove blocking ip (%lu:%u , %lu:%u)\n", migration_info->peer_addr, ntohs(migration_info->peer_port), migration_info->self_addr, ntohs(migration_info->self_port));
            // remove blocking rule installed duirng serialization
            rc = remove_redirection_ebpf(migration_info->peer_addr, migration_info->self_addr,
                                         migration_info->peer_port, migration_info->self_port);
            assert(rc == 0);
        }

        //if (handoff_out_ctx->client->from_migrate == -1) {
        //    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "HANDOFF_OUT Received migration respond for HANDOFF_BACK or RESET, exit directly");
        //    ngx_close_connection(c);
        //    return;
        //}

        size_t header_len = snprintf(NULL, 0, "PUT / HTTP/1.1\r\nHost: n12-cx4:79\r\nContent-Length: 5\r\nAccept: */*\r\n\r\nDONE");
        c->send_buffer_len = header_len + 1;
        //ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "reply fake server redirection ready!");
        c->send_buffer = calloc(c->send_buffer_len, sizeof(uint8_t));
        snprintf((char*)c->send_buffer, c->send_buffer_len, "PUT / HTTP/1.1\r\nHost: n12-cx4:79\r\nContent-Length: 5\r\nAccept: */*\r\n\r\nDONE");

        // no longer need
        socket_serialize__free_unpacked(migration_info, NULL);

        rc = ngx_add_event(c->write, NGX_WRITE_EVENT, NGX_LEVEL_EVENT); 
        assert(rc == NGX_OK);
    }
}

static void handoff_out_write_handler(ngx_event_t *ev) {
    int rc = 0;
    size_t sent = 0;
    ngx_connection_t *c = ev->data;
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0, "upstream sock write event fd=%d", c->fd);

    sent = c->send(c, c->send_buffer + c->sent, c->send_buffer_len - c->sent);
    if (sent == NGX_EAGAIN || c->sent < c->send_buffer_len) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0, "upstream sock write event fd=%d sent %d/%ld", c->fd, c->sent, c->send_buffer_len);
        rc = ngx_add_event(ev, NGX_WRITE_EVENT, NGX_LEVEL_EVENT); 
        assert(rc == 0);
    }

    if (c->sent >= c->send_buffer_len) {
        free(c->send_buffer);
        c->send_buffer = NULL;
        c->sent = 0;
        c->send_buffer_len = 0;
        rc = ngx_del_event(ev, NGX_WRITE_EVENT, NGX_CLEAR_EVENT); 
        assert(rc == 0);
    }
}

void handoff_out_connect_handler(ngx_event_t *ev) {
    int rc = -1;
    ngx_connection_t *c = ev->data;
    ev->ready = 1;
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "upstream sock connected fd=%d", c->fd);
    
    c->read->handler  = handoff_out_read_handler;
    c->write->handler = handoff_out_write_handler;
    
    //if (!c->handoff_out_ctx->is_fd_connected) {
    // init handoff out
    c->handoff_out_ctx->is_fd_connected = true;
    c->handoff_out_ctx->is_fd_in_epoll = false;
    c->handoff_out_ctx->fd = c->fd;
    
    // send HTTP req to upstream
    size_t header_len = snprintf(NULL, 0, "PUT / HTTP/1.1\r\nHost: n12-cx4:79\r\nAccept: */*\r\nContent-length: %d\r\n\r\n", c->handoff_out_ctx->client->proto_buf_len);
    c->send_buffer_len = header_len + c->handoff_out_ctx->client->proto_buf_len;
    //ngx_log_debug3(NGX_LOG_DEBUG_HTTP,c->log, 0, "header length=%d protbuf len=%d total len=%d", header_len, c->handoff_out_ctx->client->proto_buf_len, c->send_buffer_len);
    c->send_buffer = calloc(c->send_buffer_len, sizeof(uint8_t));
    
    snprintf((char*)c->send_buffer, c->send_buffer_len, "PUT / HTTP/1.1\r\nHost: n12-cx4:79\r\nAccept: */*\r\nContent-length: %d\r\n\r\n", c->handoff_out_ctx->client->proto_buf_len);
    memcpy(&c->send_buffer[header_len], c->handoff_out_ctx->client->proto_buf, c->handoff_out_ctx->client->proto_buf_len);
    
    //ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, " protobuf %s", &c->send_buffer[header_len]+sizeof(uint32_t));
    
    c->recv_buffer_len = 8192 * sizeof(uint8_t);
    c->read->available = c->recv_buffer_len;
    //c->recv_buffer = malloc(c->read->available);
    c->recv_buffer = malloc(c->recv_buffer_len);
    
    rc = ngx_add_event(ev, NGX_WRITE_EVENT, NGX_LEVEL_EVENT);
    assert(rc == 0);
    //ngx_http_finalize_request(handoff_out_ctx->req_to_free, NGX_ERROR);
}

ngx_int_t ngx_http_handoff_out_handler(ngx_http_request_t *r) {
    ngx_int_t rc;
    ngx_connection_t *upstream_conn;
    struct handoff_out *handoff_out_ctx = r->connection->handoff_out_ctx;
    struct handoff_in  *handoff_in_ctx  = r->connection->handoff_in_ctx;
    ngx_http_handoff_main_conf_t *my_conf = ngx_http_get_module_main_conf(r, ngx_http_handoff_module);
    size_t pool_size = r->connection->listening->pool_size;

    if (handoff_out_ctx == NULL) {
        //struct handoff_out *handoff_out_ctx = ngx_pcalloc(r->connection->pool, sizeof(struct handoff_out));
        struct handoff_out *handoff_out_ctx = calloc(1, sizeof(struct handoff_out));
        handoff_out_ctx->ngx_conf = my_conf;
        struct http_client *client = create_http_client(0, r->connection->fd);

        struct sockaddr_in* addr = (struct sockaddr_in*)r->connection->sockaddr;
        rc = get_mac_address(my_conf->ifname, *addr, client->client_mac);
        assert(rc == 0);

        client->client_addr = addr->sin_addr.s_addr;
        client->client_port = addr->sin_port;
        strncpy(client->uri_str, (char*)r->uri.data, r->uri.len);
        client->uri_str[r->uri.len] = '\0';
        client->uri_str_len = r->uri.len;

        struct sockaddr_in *sockaddr_to_connect;
        //if (handoff_in_ctx == NULL || handoff_in_ctx->client_for_originaldone == NULL) {
        if (handoff_in_ctx == NULL) {
            // fresh connection - init handoff
            char *tmp0 = strstr((char*)r->uri.data + sizeof(char), "/");

            client->to_migrate = my_random(1, handoff_out_ctx->ngx_conf->num_peers) - 1;
            // overwrite to_migrate if found in URI
            if (tmp0) {
                size_t len = tmp0 - ((char*)r->uri.data + sizeof(char));
                if (len < r->uri.len) {
                    char init_migrate_target_str[10];
                    strncpy(init_migrate_target_str, (char*)r->uri.data + sizeof(char), len);
                    client->to_migrate = atoi(init_migrate_target_str);
                }
            }

ngx_log_debug(NGX_LOG_DEBUG_EVENT, r->connection->log, 0, "to handoff...\n");
            client->from_migrate = -1;
            client->fd = r->connection->fd;
            sockaddr_to_connect = &handoff_out_ctx->ngx_conf->peer_sockaddr[client->to_migrate];
        }
        else {
ngx_log_debug(NGX_LOG_DEBUG_EVENT, r->connection->log, 0, "to handoff back...\n");
            // migrated connection - handoff back
            client->from_migrate = handoff_in_ctx->ngx_conf->my_id;
            client->to_migrate = -1;
            client->fd = handoff_in_ctx->restored_conn->fd;
            sockaddr_to_connect = &handoff_in_ctx->frontend_sockaddr;
        }

        ngx_log_t *listener_log = &r->connection->listening->log;
        handoff_out_ctx->client = client;
        ngx_reusable_connection(r->connection, 0);
        handoff_out_serialize(handoff_out_ctx->client, r->connection->log);
        rc = connect_to_upstream(sockaddr_to_connect, handoff_out_ctx, pool_size, handoff_out_connect_handler, listener_log, &upstream_conn);
        if (rc != NGX_OK && rc != NGX_AGAIN) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno, " connect to upstream fail");
            return NGX_ERROR;
        }
        //ngx_pfree(r->connection->pool, handoff_out_ctx);
        free(handoff_out_ctx); // this is copyed to upstream conn by connect_to_upstream()
    }

    //ngx_http_finalize_request(r, NGX_ERROR);
    return NGX_OK;
}
