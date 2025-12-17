#ifndef __QUEUE_H__
#define __QUEUE_H__

#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "zlog.h"

extern zlog_category_t *zlog_queue;

//#ifdef DO_NBTC
//typedef enum
//{
//        RULE_INSERT,
//        RULE_REMOVE
//} operation_t;

struct __attribute__((packed)) rule_args {
	volatile bool skip;
	volatile bool in_progress;
//	operation_t op;
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t new_src_ip;
	uint8_t new_src_mac[6];
	uint32_t new_dst_ip;
	uint8_t new_dst_mac[6];
	uint16_t new_src_port;
	uint16_t new_dst_port;
	bool block;
	bool hw_offload;
};


typedef struct rule_args rule_args_t;

typedef struct
{
        int size;
        int count;
        int head;
        int tail;
        rule_args_t *buffer;
        pthread_mutex_t lock;
        pthread_cond_t not_empty;
        pthread_cond_t not_full;
} rule_queue_t;

void rule_queue_init(rule_queue_t *q, int q_size);
void rule_queue_destroy(rule_queue_t *q);
bool rule_enqueue(rule_queue_t *q, rule_args_t *arg);
bool rule_in_queue(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, rule_queue_t *q);
void *rule_q_consumer(void *queue);

#endif
