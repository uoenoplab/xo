#ifndef __HANDOFF_IN_H__
#define __HANDOFF_IN_H__

#include <ngx_http_request.h>

ngx_int_t ngx_http_handoff_in_handler(ngx_http_request_t *r);
ngx_int_t xo_handle_http_request(ngx_http_request_t *r);

#endif
