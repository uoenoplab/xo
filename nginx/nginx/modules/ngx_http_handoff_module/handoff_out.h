#ifndef __HANDOFF_OUT__
#define __HANDOFF_OUT__

ngx_int_t ngx_http_handoff_out_handler(ngx_http_request_t *r);
void handoff_out_connect_handler(ngx_event_t *ev);

#endif
