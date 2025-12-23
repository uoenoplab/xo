#include <stdint.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>

#include <errno.h>
#include <linux/bpf.h>
#include <pthread.h>

#include "private/common.h"
#include "ebpf_forward.h"
#include "bpf/bpf.h"

#define DEBUG

static struct flow *my_flows = NULL;
int map_fd = -1;
static pthread_rwlock_t lock;

#ifdef PROFILE
#include <time.h>
// https://stackoverflow.com/questions/68804469/subtract-two-timespec-objects-find-difference-in-time-or-duration
static double diff_timespec(const struct timespec *time1, const struct timespec *time0) {
	return (time1->tv_sec - time0->tv_sec) + (time1->tv_nsec - time0->tv_nsec) / 1000000000.0;
}
#endif

int apply_redirection_ebpf_str(const char *src_ip_str, const char *dst_ip_str, const uint16_t sport, const uint16_t dport,
			const char *new_src_ip_str, const char *new_src_mac_str, const char *new_dst_ip_str, const char *new_dst_mac_str,
			const uint16_t new_sport, const uint16_t new_dport, const bool block)
{
	uint32_t src_ip;
	uint32_t dst_ip;

	uint32_t new_src_ip;
	uint32_t new_dst_ip;

	uint8_t new_src_mac[6];
	uint8_t new_dst_mac[6];

	hwaddr_aton(new_src_mac_str, new_src_mac);
	hwaddr_aton(new_dst_mac_str, new_dst_mac);

	inet_pton(AF_INET, src_ip_str, &src_ip);
	inet_pton(AF_INET, dst_ip_str, &dst_ip);
	inet_pton(AF_INET, new_src_ip_str, &new_src_ip);
	inet_pton(AF_INET, new_dst_ip_str, &new_dst_ip);

	return apply_redirection_ebpf(src_ip, dst_ip, htons(sport), htons(dport), new_src_ip, new_src_mac, new_dst_ip, new_dst_mac, htons(new_sport), htons(new_dport), block);
}


int apply_redirection_ebpf(const uint32_t src_ip, const uint32_t dst_ip, const uint16_t sport, const uint16_t dport,
			const uint32_t new_src_ip, const uint8_t *new_src_mac, const uint32_t new_dst_ip, const uint8_t *new_dst_mac,
			const uint16_t new_sport, const uint16_t new_dport, const bool block)
{
	if (initialized == -1) {
		fprintf(stderr, "WARNING: libforward-ebpf: library not initialized\n");
		return -1;
	}
	
	if(map_fd < 0) {
		fprintf(stderr, "WARNING: libforward-ebpf: invalid eBPF map fd\n");
		return -1;
	}
	if (pthread_rwlock_wrlock(&lock) != 0) { printf("can't get wrlock"); exit(1); }

#ifdef PROFILE
	struct timespec start_time, end_time;
	fprintf(stderr, "Inserting rule...\n");
	clock_gettime(CLOCK_MONOTONIC, &start_time);
#endif

	int ret = -1;
	struct flow *this_flow = (struct flow*)calloc(1, sizeof(struct flow));
	struct flow *existing_flow = NULL;
	bzero(this_flow, sizeof(struct flow_key));

	this_flow->flow_id.src_ip = src_ip;
	this_flow->flow_id.dst_ip = dst_ip;
	this_flow->flow_id.src_port = sport;
	this_flow->flow_id.dst_port = dport;
	HASH_FIND(hh, my_flows, &(this_flow->flow_id), sizeof(struct flow_key), existing_flow);

	struct redirection redirected_flow;
	bzero(&redirected_flow, sizeof(struct redirection));
	redirected_flow.new_src_ip = new_src_ip;
	redirected_flow.new_dst_ip = new_dst_ip;
	memcpy(redirected_flow.new_src_mac, new_src_mac, sizeof(redirected_flow.new_src_mac));
	memcpy(redirected_flow.new_dst_mac, new_dst_mac, sizeof(redirected_flow.new_dst_mac));
	redirected_flow.new_sport = new_sport;
	redirected_flow.new_dport = new_dport;
	redirected_flow.block = block ? 1 : 0;

	if (existing_flow && existing_flow->handle == UINT32_MAX) {
#ifdef DEBUG
		fprintf(stderr, "INFO: libforward-ebpf: updating existing eBPF flow (%d,%d)...\n", ntohs(sport), ntohs(dport));
#endif
		ret = bpf_map_update_elem(map_fd, &(this_flow->flow_id), &redirected_flow, BPF_EXIST);
		free(this_flow);
	}
	else {
#ifdef DEBUG
		fprintf(stderr, "INFO: libforward-ebpf: adding eBPF flow (%d,%d)...\n", ntohs(sport), ntohs(dport));
#endif
		ret = bpf_map_update_elem(map_fd, &(this_flow->flow_id), &redirected_flow, BPF_NOEXIST);
		this_flow->handle = UINT32_MAX;
		HASH_ADD(hh, my_flows, flow_id, sizeof(struct flow_key), this_flow);
	}

#ifdef PROFILE
	clock_gettime(CLOCK_MONOTONIC, &end_time);
	fprintf(stderr, "Insertion time    : %f s\n", diff_timespec(&end_time, &start_time));
#endif

	pthread_rwlock_unlock(&lock);
	return ret;
}

int remove_redirection_ebpf_str(const char *src_ip_str, const char *dst_ip_str, const uint16_t sport, const uint16_t dport)
{
	uint32_t src_ip;
	uint32_t dst_ip;

	inet_pton(AF_INET, src_ip_str, &src_ip);
	inet_pton(AF_INET, dst_ip_str, &dst_ip);

	return remove_redirection_ebpf(src_ip, dst_ip, htons(sport), htons(dport));
}


int remove_redirection_ebpf(const uint32_t src_ip, const uint32_t dst_ip, const uint16_t sport, const uint16_t dport)
{
	if (initialized == -1) {
		fprintf(stderr, "WARNING: libforward-epbf: library not initialized\n");
		return -1;
	}

	if(map_fd < 0) {
		fprintf(stderr, "WARNING: libforward-ebpf: invalid eBPF map fd\n");
		return -1;
	}
	if (pthread_rwlock_wrlock(&lock) != 0) { printf("can't get wrlock"); exit(1); }

#ifdef PROFILE
	struct timespec start_time, end_time;
	struct timespec hash_end_time;

	fprintf(stderr, "Removing rule...\n");
	clock_gettime(CLOCK_MONOTONIC, &start_time);
#endif

	/* check if flow is in system */
	int ret = -1;
	struct flow *this_flow = (struct flow*)calloc(1, sizeof(struct flow));
	struct flow *existing_flow;

	bzero(this_flow, sizeof(struct flow));
	this_flow->flow_id.src_ip = src_ip;
	this_flow->flow_id.dst_ip = dst_ip;
	this_flow->flow_id.src_port = sport;
	this_flow->flow_id.dst_port = dport;
	HASH_FIND(hh, my_flows, &(this_flow->flow_id), sizeof(struct flow_key), existing_flow);

#ifdef PROFILE
	clock_gettime(CLOCK_MONOTONIC, &hash_end_time);
#endif

	if (!existing_flow) {
		fprintf(stderr, "ERROR: libforward-ebpf: cannot delete unregistered flow\n");
		free(this_flow);
		exit(1);
		ret = 2;
	}
	else {
		ret = bpf_map_delete_elem(map_fd, &(existing_flow->flow_id));
		free(this_flow);
		HASH_DEL(my_flows, existing_flow);
#ifdef DEBUG
		fprintf(stderr, "INFO: libforward-epbf: removing eBPF existing flow (%d,%d)...\n", ntohs(sport), ntohs(dport));
#endif
		free(existing_flow);
	}

#ifdef PROFILE
	clock_gettime(CLOCK_MONOTONIC, &end_time);
	fprintf(stderr, "Hash time     : %f s\n", diff_timespec(&hash_end_time, &start_time));
	fprintf(stderr, "Deletion time : %f s\n", diff_timespec(&end_time, &hash_end_time));
	fprintf(stderr, "Total time    : %f s\n\n", diff_timespec(&end_time, &start_time));
#endif

	pthread_rwlock_unlock(&lock);
	return ret;
}

int fini_forward_ebpf()
{
	if (initialized != 1) {
		fprintf(stderr, "WARNING: libforward-epbf: library not initialized\n");
		return 1;
	}

	struct flow *current_flow, *tmp;
//	if (pthread_rwlock_rdlock(&lock) != 0) printf("can't get wrlock");
	HASH_ITER(hh, my_flows, current_flow, tmp) {
		remove_redirection_ebpf(current_flow->flow_id.src_ip, current_flow->flow_id.dst_ip, current_flow->flow_id.src_port, current_flow->flow_id.dst_port);
	}
//	pthread_rwlock_unlock(&lock);

	return 0;
}
