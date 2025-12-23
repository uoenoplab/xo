#ifndef __EBPF_FORWARD_H__
#define __EBPF_FORWARD_H__

#include <stdint.h>
#include <stdbool.h>

int fini_forward_ebpf();

int remove_redirection_ebpf_str(const char *src_ip_str, const char *dst_ip_str, const uint16_t sport, const uint16_t dport);

int remove_redirection_ebpf(const uint32_t src_ip, const uint32_t dst_ip,
			const uint16_t sport, const uint16_t dport);

int apply_redirection_ebpf_str(const char *src_ip_str, const char *dst_ip_str, const uint16_t sport, const uint16_t dport, const char *new_src_ip_str, const char *new_src_mac_str, const char *new_dst_ip_str, const char *new_dst_mac_str, const uint16_t new_sport, const uint16_t new_dport, const bool block);

int apply_redirection_ebpf(const uint32_t src_ip, const uint32_t dst_ip,
		      const uint16_t sport, const uint16_t dport,
		      const uint32_t new_src_ip, const uint8_t *new_src_mac, const uint32_t new_dst_ip, const uint8_t *new_dst_mac,
		      const uint16_t new_sport, const uint16_t new_dport,
		      const bool block);

#endif
