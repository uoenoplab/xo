#ifndef __OBJECT_STORE_H__
#define __OBJECT_STORE_H__

#include <rados/librados.h>
#include <uriparser/Uri.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "http_client.h"
#include "md5.h"

#include "zlog.h"

extern zlog_category_t *zlog_object_store;

void put_object(struct http_client *client, const char *buf, size_t length);
void delete_objects(struct http_client *client, const char *buf, size_t length);

void init_object_put_request(struct http_client *client);
void init_object_get_request(struct http_client *client);
void init_objects_delete_request(struct http_client *client);

void complete_head_request(struct http_client *client, const char *datetime_str);
void complete_post_request(struct http_client *client, const char *datetime_str);
void complete_delete_request(struct http_client *client, const char *datetime_str);
void complete_put_request(struct http_client *client, const char *datetime_str);
void complete_get_request(struct http_client *client, const char *datetime_str);

#endif
