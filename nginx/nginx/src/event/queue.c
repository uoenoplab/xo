#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>

#include <arpa/inet.h>

#include "queue.h"
#include "forward.h"

//zlog_category_t *zlog_queue;

void rule_queue_init(rule_queue_t *q, int q_size)
{
	q->size= q_size;
	q->count = 0;
	q->head = 0;
	q->tail = 0;

	q->buffer = (rule_args_t *)malloc(q->size * sizeof(struct rule_args));

	pthread_mutex_init(&q->lock, NULL);
	pthread_cond_init(&q->not_empty, NULL);
	pthread_cond_init(&q->not_full, NULL);
}

void rule_queue_destroy(rule_queue_t *q)
{
	free(q->buffer);
	pthread_mutex_destroy(&q->lock);
	pthread_cond_destroy(&q->not_empty);
	pthread_cond_destroy(&q->not_full);
}

bool rule_enqueue(rule_queue_t *q, rule_args_t *arg)
{
//clock_gettime(CLOCK_MONOTONIC, &start_time);
	pthread_mutex_lock(&q->lock);
	if (q->count == q->size)
	{
		pthread_mutex_unlock(&q->lock);
		//zlog_debug(zlog_queue, "q->tail %d, q->count %d, queue full!!!", q->tail, q->count);
		return false;
	}
	else
	{
		memcpy(&q->buffer[q->tail], arg, sizeof(rule_args_t));
		q->tail = (q->tail + 1) % q->size;
		q->count++;
		pthread_cond_signal(&q->not_empty);
		//zlog_debug(zlog_queue, "Enqueue rule (%d,%d) (head=%d,tail=%d,count=%d)", ntohs(arg->src_port), ntohs(arg->dst_port), q->head, q->tail, q->count);
		pthread_mutex_unlock(&q->lock);
		return true;
	}
}

bool rule_in_queue(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, rule_queue_t *q)
{
	pthread_mutex_lock(&q->lock);
	for (int idx = 0; idx < q->count; idx++) {
		int i = (q->head + idx) % q->size;
		if (q->buffer[i].src_ip == src_ip && q->buffer[i].dst_ip == dst_ip &&
			q->buffer[i].src_port == src_port && q->buffer[i].dst_port == dst_port && q->buffer[i].skip == false) {
			q->buffer[i].skip = true;
			//zlog_debug(zlog_queue, "Marking flow (%d) to skip insertion (head=%d,tail=%d,count=%d)", ntohs(q->buffer[i].src_port), q->head, q->tail, q->count);
			pthread_mutex_unlock(&q->lock);
			return true;
		}
	}
	pthread_mutex_unlock(&q->lock);
	return false; //ret;
}

void *rule_q_consumer(void *queue)
{
	rule_queue_t *q = (rule_queue_t *)queue;
	//zlog_info(zlog_queue, "TC-worker queue started (head=%d,tail=%d,count=%d)", q->head, q->tail, q->count);

	for (;;)
	{
		rule_args_t arg;
		pthread_mutex_lock(&q->lock);
		while (q->count == 0)
		{
			pthread_cond_wait(&q->not_empty, &q->lock);
		}

		memcpy(&arg, &q->buffer[q->head], sizeof(rule_args_t));
		q->count--;
		q->head = (q->head + 1) % q->size;

		if (arg.skip)
		{
			//zlog_debug(zlog_queue, "Skipped client port %d (head=%d,tail=%d,count=%d)", ntohs(arg.src_port), q->head, q->tail, q->count);
			pthread_cond_signal(&q->not_full);
			pthread_mutex_unlock(&q->lock);
			continue;
		}

		pthread_mutex_unlock(&q->lock);

		//zlog_debug(zlog_queue, "Applying redirection rule (%d,%d) (head=%d,tail=%d,count=%d)", ntohs(arg.src_port), ntohs(arg.dst_port), q->head, q->tail, q->count);
		int ret = apply_redirection(
			arg.src_ip, arg.dst_ip,
			arg.src_port, arg.dst_port,
			arg.new_src_ip, arg.new_src_mac,
			arg.new_dst_ip, arg.new_dst_mac,
			arg.new_src_port, arg.new_dst_port,
			arg.block, arg.hw_offload);
		assert(ret == 0);
	}

	//zlog_debug(zlog_queue, "Stopping TC-rule consumer thread");
	return NULL;
}
