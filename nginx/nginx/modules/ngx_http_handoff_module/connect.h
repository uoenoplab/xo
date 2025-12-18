#ifndef __CONNECT_H__
#define __CONNECT_H__

#include <ngx_config.h>
#include <ngx_http_request.h>

void handoff_out_connect_handler(ngx_event_t *ev);
//ngx_int_t connect_to_upstream(ngx_http_request_t *r,
//                              struct handoff_out *handoff_out_ctx,
//                              ngx_event_handler_pt connect_handler,
//                              ngx_connection_t **conn);

ngx_int_t connect_to_upstream(struct sockaddr_in *sockaddr,
                              struct handoff_out *handoff_out_ctx,
                              size_t pool_size,
                              ngx_event_handler_pt connect_handler,
                              ngx_log_t *log,
                              ngx_connection_t **conn);

void init_reset_request(ngx_connection_t *c);

#endif
