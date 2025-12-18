#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdint.h>
#include <netinet/in.h>

int find_backend_id_by_address(uint32_t ip_addr, struct sockaddr_in *peer_addrs, int num_peers);
int my_random(int min, int max);
void print_mac_address(unsigned char *mac);
int get_mac_address(const char *ifname, struct sockaddr_in addr, uint8_t *mac);
void hexdump(const char *title, void *buf, size_t len);
double elapsed_time(struct timespec a, struct timespec b);
void get_datetime_str(char *buf, size_t length);
void convertToISODateTime(const char* inputDateTime, char* outputISODateTime);
void unescapeHtml(char* str);

#endif
