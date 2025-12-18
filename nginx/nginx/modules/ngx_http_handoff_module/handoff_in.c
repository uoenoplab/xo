#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_handoff_module.h"
#include "handoff_in.h"
#include "handoff_out.h"
#include "connect.h"
#include "util.h"

void ngx_http_handoff_in_init(ngx_http_request_t *r);
ngx_int_t xo_handle_http_request(ngx_http_request_t *r);

uint8_t *eight_MB;

void ngx_http_handoff_in_init(ngx_http_request_t *r)
{
    off_t         len;
    ngx_buf_t    *b;
    ngx_int_t     rc;
    ngx_chain_t  *in, out;
    struct handoff_in *handoff_in_ctx;
    ngx_connection_t *c, *restored_conn = NULL;
    ngx_http_handoff_main_conf_t *my_conf;

    c = r->connection;
    handoff_in_ctx = c->handoff_in_ctx;
    my_conf = handoff_in_ctx->ngx_conf;

    if (r->request_body == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    len = 0;

    for (in = r->request_body->bufs; in; in = in->next) {
        len += ngx_buf_size(in->buf);
    }

    b = ngx_create_temp_buf(r->pool, NGX_OFF_T_LEN);
    if (b == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    b->last = ngx_sprintf(b->pos, "%O", len);
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0, "recv http event fd=%d length=%d ready_len=%d", c->fd, r->headers_in.content_length_n, len);

    handoff_in_ctx->recv_protobuf_len      = r->headers_in.content_length_n;
    handoff_in_ctx->recv_protobuf_received = r->headers_in.content_length_n;
    SocketSerialize *migration_info = socket_serialize__unpack(NULL, handoff_in_ctx->recv_protobuf_len-sizeof(uint32_t), r->request_body->bufs->buf->start+sizeof(uint32_t));
    if (migration_info == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "fail to unpack protobuf");
        exit(EXIT_FAILURE);
    }
    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "unpack protobuf successful");

    // find out where the request came from
    handoff_in_ctx->osd_arr_index = find_backend_id_by_address(((struct sockaddr_in*)c->sockaddr)->sin_addr.s_addr, my_conf->peer_sockaddr, my_conf->num_peers);

    if (migration_info->msg_type == HANDOFF_BACK_REQUEST) {
        // round robin
        int to_migrate = (handoff_in_ctx->osd_arr_index + 1 + my_conf->num_peers) % my_conf->num_peers;
        handoff_out_serialize_rehandoff(&handoff_in_ctx->client_to_handoff_again, migration_info, &my_conf->my_sockaddr, to_migrate, my_conf->my_id);
//printf("HANDOFF_BACK_REQUEST: from %d: rehandoff to %d\n", handoff_in_ctx->osd_arr_index, to_migrate);
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "HANDOFF_BACK_RQUEST: rehandoff to %d\n", to_migrate);
        goto reply_handoff;
    }
    else if (migration_info->msg_type == HANDOFF_REQUEST) {
        handoff_in_deserialize(handoff_in_ctx, migration_info, c->log);
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "HANDOFF_REQUEST\n");
//printf("HANDOFF_REQUEST: from %d\n", handoff_in_ctx->osd_arr_index);
    }
    else if (migration_info->msg_type == HANDOFF_RESET_REQUEST) {
        handoff_in_ctx->osd_arr_index = find_backend_id_by_address(((struct sockaddr_in*)c->sockaddr)->sin_addr.s_addr, my_conf->peer_sockaddr, my_conf->num_peers);
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "HANDOFF_RESET\n");
//printf("HANDOFF_RESET_REQUEST: from %d\n", handoff_in_ctx->osd_arr_index);
        goto reply_handoff;
    }
    else {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "HANDOFF_TYPE unknown!!!!!!!!!\n");
        exit(1);
    }

    restored_conn = ngx_get_connection(handoff_in_ctx->client_for_originaldone->fd, c->log);
    assert(restored_conn != NULL);

    ngx_reusable_connection(restored_conn, 0);

    // create pool for connection
    restored_conn->pool = ngx_create_pool(c->listening->pool_size, c->log);
    assert(restored_conn->pool != NULL);

    struct sockaddr_in* restored_conn_addr = (struct sockaddr_in*)ngx_pcalloc(restored_conn->pool, sizeof(struct sockaddr_in));
    //struct sockaddr_in* restored_conn_addr = (struct sockaddr_in*)calloc(1, sizeof(struct sockaddr_in));
    restored_conn->sockaddr = (struct sockaddr*)restored_conn_addr;
 
    restored_conn_addr->sin_addr.s_addr = handoff_in_ctx->client_for_originaldone->client_addr;
    restored_conn_addr->sin_port        = handoff_in_ctx->client_for_originaldone->client_port;
    restored_conn_addr->sin_family      = AF_INET;

    // mark this connection as handed off
    //restored_conn->handoff_in_ctx = ngx_pcalloc(restored_conn->pool, sizeof(struct handoff_in));
    restored_conn->handoff_in_ctx = calloc(1, sizeof(struct handoff_in));
    restored_conn->handoff_in_ctx->client_for_originaldone = NULL;

    ngx_log_t *log = ngx_pcalloc(restored_conn->pool, sizeof(ngx_log_t));
    //ngx_log_t *log = calloc(1, sizeof(ngx_log_t));
    assert(restored_conn->log != NULL);
    *log = c->listening->log;

    restored_conn->recv = ngx_recv;
    restored_conn->send = ngx_send;
    restored_conn->recv_chain = ngx_recv_chain;
    restored_conn->send_chain = ngx_send_chain;

    restored_conn->log = log;
    restored_conn->pool->log = log;

    restored_conn->socklen = sizeof(struct sockaddr_in);
    restored_conn->listening      = c->listening;
    restored_conn->local_sockaddr = c->listening->sockaddr;
    restored_conn->local_socklen  = c->listening->socklen;

    restored_conn->type = SOCK_STREAM;

    restored_conn->read->ready = 1;

    restored_conn->read->log = log;
    restored_conn->write->log = log;

    restored_conn->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    restored_conn->start_time = ngx_current_msec;
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "restored socket fd=%d", restored_conn->fd);

    if (ngx_add_conn) {
        if (ngx_add_conn(restored_conn) == NGX_ERROR) {
            //ngx_debug_accepted_connection(restored_conn);
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "Fail to add restored socket to epoll loop");
            return;
        }
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "aded restored socket to epoll loop");
    }

    //log->data = NULL;
    //log->handler = NULL;
    c->listening->handler(restored_conn);

reply_handoff:
    if (migration_info->msg_type == HANDOFF_REQUEST) {
        // store the sockaddr of the front end
        memset(&handoff_in_ctx->frontend_sockaddr, 0, sizeof(struct sockaddr_in));
        handoff_in_ctx->frontend_sockaddr.sin_addr.s_addr = migration_info->self_addr;
        handoff_in_ctx->frontend_sockaddr.sin_port        = my_conf->peer_sockaddr[0].sin_port;
        handoff_in_ctx->frontend_sockaddr.sin_family      = AF_INET;

        // src IP modiication
        rc = apply_redirection_ebpf(my_conf->my_sockaddr.sin_addr.s_addr, migration_info->peer_addr,
                                    migration_info->self_port, migration_info->peer_port,
                                    migration_info->self_addr, my_conf->my_mac, migration_info->peer_addr, (uint8_t *)&migration_info->peer_mac,
                                    htons(ntohs(migration_info->self_port) - 1 - 1), migration_info->peer_port, false); // offst self port
        assert(rc == 0);
ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0, "apply src ip modification (%u:%u , %lu:%u)\n", my_conf->my_sockaddr.sin_addr.s_addr, ntohs(migration_info->self_port), migration_info->peer_addr, ntohs(migration_info->peer_port));
//printf("apply src ip modification (%u:%u , %lu:%u)\n", my_conf->my_sockaddr.sin_addr.s_addr, ntohs(migration_info->self_port), migration_info->peer_addr, ntohs(migration_info->peer_port));
    }
    //else if (migration_info->msg_type == HANDOFF_BACK_REQUEST || migration_info->msg_type == HANDOFF_RESET_REQUEST) {
    else if (migration_info->msg_type == HANDOFF_RESET_REQUEST) {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0, "Handoff back / reset (%d,%d)", ntohs(migration_info->peer_port), ntohs(migration_info->self_port) - 1 - 1);
        memcpy(&handoff_in_ctx->frontend_sockaddr, &my_conf->my_sockaddr, sizeof(struct sockaddr_in));
        // remove redirection if this is handoff back
        // TODO FIX THIS
        //rc = remove_redirection_ebpf(migration_info->peer_addr, my_conf->my_sockaddr.sin_addr.s_addr,
        rc = remove_redirection_ebpf(migration_info->peer_addr, my_conf->my_sockaddr.sin_addr.s_addr,
                                     migration_info->peer_port, htons(ntohs(migration_info->self_port) - 1 - 1));
        assert(rc == 0);
ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0, "remove redir (%lu:%u , %u:%u)\n", migration_info->peer_addr, ntohs(migration_info->peer_port), my_conf->my_sockaddr.sin_addr.s_addr, ntohs(migration_info->self_port) - 1 -1);
//printf("remove redir (%lu:%u , %u:%u)\n", migration_info->peer_addr, ntohs(migration_info->peer_port), my_conf->my_sockaddr.sin_addr.s_addr, ntohs(migration_info->self_port) - 1 -1);
    }

    // build response proto_buf
    SocketSerialize migration_info_resp = SOCKET_SERIALIZE__INIT;
    migration_info_resp.msg_type = HANDOFF_DONE;

    migration_info_resp.self_addr = migration_info->self_addr;
    migration_info_resp.peer_addr = migration_info->peer_addr;

    // encode self mac in response for orginal server to perform redirection
    memcpy(&(migration_info_resp.peer_mac), my_conf->my_mac, sizeof(uint8_t) * 6);

    // reply object size for original server to determine redirection method
    //migration_info_resp.object_size = migration_info->object_size;
    migration_info_resp.self_port = migration_info->self_port;
    migration_info_resp.peer_port = migration_info->peer_port;

    int proto_len = socket_serialize__get_packed_size(&migration_info_resp);
    uint32_t net_proto_len = htonl(proto_len);
    //uint8_t *proto_buf = ngx_pcalloc(r->connection->pool, sizeof(net_proto_len) + proto_len);
    uint8_t *proto_buf = malloc(sizeof(net_proto_len) + proto_len);
    socket_serialize__pack(&migration_info_resp, proto_buf + sizeof(net_proto_len));
    // add length of proto_buf at the begin
    memcpy(proto_buf, &net_proto_len, sizeof(net_proto_len));

    handoff_in_ctx->send_protobuf = proto_buf;
    handoff_in_ctx->send_protobuf_len = sizeof(net_proto_len) + proto_len;
    handoff_in_ctx->restored_conn = restored_conn;

    // done with handoff_in_ctx, store in restored conn for handoff back
    // subsequent requests will use the handoff_in_ctx in the upstream_conn, set to false
    if (migration_info->msg_type == HANDOFF_REQUEST) {
        memcpy(restored_conn->handoff_in_ctx, handoff_in_ctx, sizeof(struct handoff_in));
        if (handoff_in_ctx->send_protobuf) {
            restored_conn->handoff_in_ctx->send_protobuf = malloc(handoff_in_ctx->send_protobuf_len);
            memcpy(restored_conn->handoff_in_ctx->send_protobuf, handoff_in_ctx->send_protobuf, handoff_in_ctx->send_protobuf_len);
        }
ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "restored conn %s\n", inet_ntoa(restored_conn->handoff_in_ctx->frontend_sockaddr.sin_addr));
        restored_conn->handoff_in_ctx->client_for_originaldone = NULL;
        //restored_conn->handoff_in_ctx->client_for_originaldone = calloc(1, sizeof(struct http_client));
        //memcpy(restored_conn->handoff_in_ctx->client_for_originaldone, handoff_in_ctx->client_for_originaldone, sizeof(struct http_client));
    }

    // current request in needs to be retured immediately, special case
    handoff_in_ctx->wait_for_originaldone = true;

    // no longer need
    socket_serialize__free_unpacked(migration_info, NULL);

    // repond to orignal server
    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return;
    }

    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type.data = (u_char *) "text/plain";
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = handoff_in_ctx->send_protobuf_len;

    // reply client
    r->connection->log->action = "reading client request line";

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    if (b == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    out.buf = b;
    out.next = NULL;

    b->pos = (u_char *) handoff_in_ctx->send_protobuf;
    b->last = b->pos + handoff_in_ctx->send_protobuf_len;
    b->memory = 1;
    b->last_buf = 1;
    //ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, " resp protobuf %s", handoff_in_ctx->send_protobuf+sizeof(uint32_t));

    rc = ngx_http_output_filter(r, &out);
    if (rc != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

     ngx_http_finalize_request(r, NGX_OK);
}

ngx_int_t xo_handle_http_request(ngx_http_request_t *r) {
    ngx_int_t rc;
    ngx_buf_t *b;
    ngx_chain_t out;

    r->request_body_in_single_buf = 1;
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    int payload_size = 0;
    if (r->uri.len > 1) {
        char *tmp = strstr((char*)r->uri.data + sizeof(char), "/");
        payload_size = atoi((char*)r->uri.data + sizeof(char));
        if (tmp) {
            size_t len = tmp - ((char*)r->uri.data + sizeof(char));
            if (len < r->uri.len) {
                payload_size = atoi(tmp + sizeof(char));
            }
        }
    }

    r->keepalive = 1;
    r->headers_out.content_type.len = sizeof("application/octet-stream") - 1;
    r->headers_out.content_type.data = (u_char *) "application/octet-stream";
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = payload_size;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    b->pos = (u_char *) eight_MB;
    b->last = b->pos + payload_size;
    b->memory = 1;
    b->last_buf = 1;

    r->connection->handoff_in_ctx->req_counter++;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Handled %d req", r->connection->handoff_in_ctx->req_counter);

    return ngx_http_output_filter(r, &out);
}

static void handoff_in_write_handler(ngx_event_t *ev) {
    int rc = 0;
    size_t sent = 0;
    ngx_connection_t *c = ev->data;
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0, "upstream sock write event fd=%d %s", c->fd, c->send_buffer);

    sent = c->send(c, c->send_buffer + c->sent, c->send_buffer_len - c->sent);
    if (sent == NGX_EAGAIN || c->sent < c->send_buffer_len) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0, "upstream sock write event fd=%d sent     %d/%ld", c->fd, c->sent, c->send_buffer_len);
        //rc = ngx_add_event(ev, NGX_WRITE_EVENT, NGX_LEVEL_EVENT);
        //assert(rc == 0);
    }

    if (c->sent >= c->send_buffer_len) {
        c->sent = 0;
        free(c->send_buffer);
        c->send_buffer = NULL;
        c->send_buffer_len = 0;
        // restore nginx's http write handler pointer
        c->write->handler = c->handoff_in_ctx->original_write_handler;
        rc = ngx_del_event(ev, NGX_WRITE_EVENT, NGX_CLEAR_EVENT);
        assert(rc == 0);
    }
}

ngx_int_t ngx_http_handoff_in_handler(ngx_http_request_t *r) {
    ngx_int_t rc;
    ngx_log_t *listener_log;
    size_t pool_size;
    struct handoff_in *handoff_in_ctx = r->connection->handoff_in_ctx;
    ngx_reusable_connection(r->connection, 0);

    if (handoff_in_ctx == NULL) {
        //handoff_in_ctx = ngx_pcalloc(r->connection->pool, sizeof(struct handoff_in));
        handoff_in_ctx = calloc(1, sizeof(struct handoff_in));
        handoff_in_ctx->ngx_conf = ngx_http_get_module_main_conf(r, ngx_http_handoff_module);
        handoff_in_ctx->req_counter = 1;
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "receve incoming handoff");
//printf("receive incoming handoff\n");

        r->request_body_in_single_buf = 1;
        r->keepalive = 1;

        // handoff_in_ctx used by ngx_http_handoff_in_int()
        r->connection->handoff_in_ctx = handoff_in_ctx;
        rc = ngx_http_read_client_request_body(r, ngx_http_handoff_in_init);
        if (rc != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }

        return NGX_OK;
    }
    else if (handoff_in_ctx != NULL && handoff_in_ctx->wait_for_originaldone) {
        if (handoff_in_ctx->client_for_originaldone && handoff_in_ctx->restored_conn) {
            // income handoff case, reply first OK to client, before finalize control connection
            ngx_connection_t *restored_conn = handoff_in_ctx->restored_conn;
            if (!restored_conn->handoff_in_ctx) return NGX_ERROR;

            handoff_in_ctx->wait_for_originaldone = false;
            if (handoff_in_ctx->client_for_originaldone == NULL) {
                // rehandoff
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "client struct is empty!!!!!!!!!!!!!!!!!!!!l ");
                exit(1);
            }
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "sending first OK to client uri: %s", handoff_in_ctx->client_for_originaldone->uri_str);

            int payload_size = 0;
            if (strlen(handoff_in_ctx->client_for_originaldone->uri_str) > 1) {
                char *tmp = strstr(handoff_in_ctx->client_for_originaldone->uri_str + sizeof(char), "/");
                payload_size = atoi(handoff_in_ctx->client_for_originaldone->uri_str + sizeof(char));
                if (tmp) {
                    payload_size = atoi(tmp + sizeof(char));
                }
                else {
                    payload_size = atoi(handoff_in_ctx->client_for_originaldone->uri_str + sizeof(char));
                }
            }

            size_t total_header_len = snprintf(NULL, 0, "HTTP/1.1 200 OK\r\nServer: nginx/1.27.3\r\nDate: Fri, 31 Jan 2025 01:26:51 GMT\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n", payload_size);
            restored_conn->send_buffer = calloc((total_header_len + 1 + payload_size + 1), sizeof(uint8_t));
            restored_conn->send_buffer_len = total_header_len + payload_size;
            //memset(restored_conn->send_buffer, 1, total_header_len * sizeof(char) + 1 + payload_size + 1);
    
            snprintf((char*)restored_conn->send_buffer, total_header_len + 1, "HTTP/1.1 200 OK\r\nServer: nginx/1.27.3\r\nDate: Fri, 31 Jan 2025 01:26:51 GMT\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n", payload_size);
 
            // keep nginx's http write handler pointer and trigger write
            restored_conn->handoff_in_ctx->original_write_handler = restored_conn->write->handler;
            restored_conn->write->handler = handoff_in_write_handler;
            rc = ngx_add_event(restored_conn->write, NGX_WRITE_EVENT, NGX_LEVEL_EVENT);
            //assert(rc == 0);
            if(rc) {
                printf("FAIL TO RESPOND TO ORIGINAL SERVER\n");
                return NGX_ERROR;
            }
        }
        else if (handoff_in_ctx->client_to_handoff_again) {
            // TODO We need to reply fake server to neutural. the remote state before init new handoff
            // TODO we need to copy the handoff_in_ctx because it is associated with the control conn request which will be freed
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, r->connection->log, 0, "preserve handoff_in_ctx before reply DONEDONE!!!!!\n");

            struct handoff_in *tmp = handoff_in_ctx;
            handoff_in_ctx = calloc(1, sizeof(struct handoff_in));
            memcpy(handoff_in_ctx, tmp, sizeof(struct handoff_in)),
            //handoff_in_ctx->send_protobuf = NULL;
            //tmp->send_protobuf = NULL;

            handoff_in_ctx->client_to_handoff_again = create_http_client(-1, tmp->client_to_handoff_again->fd);
            memcpy(handoff_in_ctx->client_to_handoff_again, tmp->client_to_handoff_again, sizeof(struct http_client));
            handoff_in_ctx->client_to_handoff_again->put_buf = malloc(0);

            if (tmp->client_to_handoff_again->proto_buf != NULL) {
                handoff_in_ctx->client_to_handoff_again->proto_buf = malloc(tmp->client_to_handoff_again->proto_buf_len);
                memcpy(handoff_in_ctx->client_to_handoff_again->proto_buf, tmp->client_to_handoff_again->proto_buf, tmp->client_to_handoff_again->proto_buf_len);
            }

            listener_log = &r->connection->listening->log;
            pool_size = r->connection->listening->pool_size;
        }
        else {
            printf("both client for originaldone and to handoff again are emtpy: must be a RESET. nothing to do\n");
        }

        rc = ngx_http_discard_request_body(r);

        ngx_chain_t out;
        ngx_buf_t *b;

        // reply in control connection
        r->keepalive = 1;
        r->headers_out.content_type.len = sizeof("text/plain") - 1;
        r->headers_out.content_type.data = (u_char *) "text/plain";
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = strlen("DONEDONE");

        b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            ngx_log_debug(NGX_LOG_DEBUG_EVENT, r->connection->log, ngx_errno, "control conn send header fail");
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }

        out.buf = b;
        out.next = NULL;

        b->pos = (u_char*)"DONEDONE";
        b->last = b->pos + strlen("DONEDONE");
        b->memory = 1;
        b->last_buf = 1;

        rc = ngx_http_output_filter(r, &out);
        assert(rc == NGX_OK);

        if (handoff_in_ctx->client_to_handoff_again) {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, r->connection->log, 0, "connecting to upstream to handoff again\n");
            // rehandoff case, do it after control with fake server has closed. corner case: rehandoff to same server
            ngx_connection_t *upstream_conn;
            //struct handoff_out *handoff_out_ctx = ngx_palloc(r->connection->pool, sizeof(struct handoff_out));
            struct handoff_out *handoff_out_ctx = calloc(1, sizeof(struct handoff_out));
            handoff_out_ctx->ngx_conf = handoff_in_ctx->ngx_conf;
 
            struct sockaddr_in *sockaddr_to_connect = &handoff_out_ctx->ngx_conf->peer_sockaddr[handoff_in_ctx->client_to_handoff_again->to_migrate];

            handoff_out_ctx->client = handoff_in_ctx->client_to_handoff_again;
            rc = connect_to_upstream(sockaddr_to_connect, handoff_out_ctx, pool_size, handoff_out_connect_handler, listener_log, &upstream_conn);
            if (rc != NGX_OK && rc != NGX_AGAIN) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno, " connect to upstream fail");
                return NGX_ERROR;
            }
            //ngx_pfree(r->connection->pool, handoff_out_ctx);
            free(handoff_out_ctx);
            free(handoff_in_ctx); // in case of rehandoff, this is a copy, the ptr inside the req connection will be freed by ngx_connection_close
        }

        //ngx_http_finalize_request(r, NGX_OK);
        return NGX_OK;
    }

    ngx_http_handoff_main_conf_t *my_conf = r->connection->handoff_in_ctx->ngx_conf;
    long int current_time = ngx_time();
//printf("timestamp %ld %ld %d\n", current_time, my_conf->last_trigger, my_conf->handoff_back_counter);

    if (my_conf->handoff_back_counter == 0) {
        if (my_conf->last_trigger == 0) {
            my_conf->last_trigger = current_time;
        }
        else if (my_conf->last_trigger != 0 && current_time - my_conf->last_trigger > 5) {
            my_conf->handoff_back_counter = 1;
printf("start to dynamic load balance: timestamp %ld %ld %d\n", current_time, my_conf->last_trigger, my_conf->handoff_back_counter);
        }
    }

    if (my_conf->handoff_back_counter && current_time - my_conf->last_trigger >= 1) {
        //uint8_t cpu_loads[my_conf->num_peers];
        //memcpy(cpu_loads, my_conf->shmaddr, sizeof(uint8_t) * my_conf->num_peers);
        //uint8_t my_load = cpu_loads[my_conf->my_id];
        uint8_t my_load = my_conf->shmaddr[my_conf->my_id];

        bool trigger_migration = false;
        for (int i = 0; i < my_conf->num_peers; i++) {
            // trigger migration is found someone with 10% lower load
            if (i != my_conf->my_id && (100-my_conf->shmaddr[i])-(100-my_load) > 10) {
printf("test migration %d(%u,%u)\n", i, my_load, my_conf->shmaddr[i]);
                trigger_migration = true;
                break;
            }
        }

        if (trigger_migration) {
            my_conf->last_trigger = ngx_time();
//            printf("trigger migration: current counter: %d ; last trigger: %ld\n", my_conf->handoff_back_counter, current_time - my_conf->last_trigger);
            return ngx_http_handoff_out_handler(r);
        }
    }

    return xo_handle_http_request(r);
}
