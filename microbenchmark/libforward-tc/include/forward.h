#ifndef __FORWARD_H__
#define __FORWARD_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

int init_forward(const char *interface_name, const char *ingress_qdisc_parent, const char *egress_qdisc_parent);
int fini_forward();

void register_pending_tc_flow(const uint32_t src_ip, const uint32_t dst_ip,
				const uint16_t sport, const uint16_t dport,
				const uintptr_t ptr);

void get_tc_flow_handle(const uint32_t src_ip, const uint32_t dst_ip,
			const uint16_t sport, const uint16_t dport,
			uintptr_t *ptr, int *status);

int64_t remove_redirection_str(const char *src_ip_str, const char *dst_ip_str,
				   const uint16_t sport, const uint16_t dport);
int64_t remove_redirection(const uint32_t src_ip, const uint32_t dst_ip,
				const uint16_t sport, const uint16_t dport);

int apply_redirection_str(const char *src_ip_str, const char *dst_ip_str,
			  const uint16_t sport_str, const uint16_t dport_str,
			  const char *new_src_ip_str, const char *new_src_mac_str, const char *new_dst_ip_str, const char *new_dst_mac_str,
			  const uint16_t new_sport_str, const uint16_t new_dport_str,
			  const bool block, const bool hw_offload);
int apply_redirection(const uint32_t src_ip, const uint32_t dst_ip,
		      const uint16_t sport, const uint16_t dport,
		      const uint32_t new_src_ip, const uint8_t *new_src_mac, const uint32_t new_dst_ip, const uint8_t *new_dst_mac,
		      const uint16_t new_sport, const uint16_t new_dport,
		      const bool block, const bool hw_offload);

#ifdef __cplusplus
}
#endif

#endif
