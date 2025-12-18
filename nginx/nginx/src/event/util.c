#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <net/if.h>

#include "util.h"

int find_backend_id_by_address(uint32_t ip_addr, struct sockaddr_in *peer_addrs, int num_peers) {
    for (int i = 0; i < num_peers; i++) {
        if (ip_addr == peer_addrs[i].sin_addr.s_addr) return i;
    }
    return -1;
}

int my_random(int min, int max){
   return min + rand() / (RAND_MAX / (max - min + 1) + 1);
}

void print_mac_address(unsigned char *mac) {
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", 
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int get_mac_address(const char *ifname, struct sockaddr_in addr, uint8_t *mac) {
    struct arpreq arp_req;
    int sock_fd;
    memset(&arp_req, 0, sizeof(struct arpreq));
    struct sockaddr_in *sin = (struct sockaddr_in *)&arp_req.arp_pa;
    sin->sin_family = AF_INET;
    sin->sin_addr = addr.sin_addr;

    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket failed");
        return -1;
    }

    //strncpy(arp_req.arp_dev, ifname, IFNAMSIZ-1);
    strncpy(arp_req.arp_dev, ifname, IF_NAMESIZE-1);
    if (ioctl(sock_fd, SIOCGARP, &arp_req) == -1) {
        close(sock_fd);
        return -1;
    }

    memcpy(mac, arp_req.arp_ha.sa_data, sizeof(uint8_t) * 6);

    close(sock_fd);
    return 0;
}

void hexdump(const char *title, void *buf, size_t len)
{
	printf("%s (%lu bytes) :\n", title, len);
	for (size_t i = 0; i < len; i++) {
		printf("%02hhX ", ((unsigned char *)buf)[i]);
		if (i % 16 == 15) printf("\n");
	}
	printf("\n");
}


double elapsed_time(struct timespec a, struct timespec b)
{
	double elapsed = (double)(a.tv_sec - b.tv_sec) + (double)(a.tv_nsec - b.tv_nsec) / (double)1e9;
	return elapsed;
}

void get_datetime_str(char *buf, size_t length)
{
	time_t now = time(0);
	struct tm tm = *gmtime(&now);
	strftime(buf, length, "%a, %d %b %Y %H:%M:%S %Z", &tm);
}

void convertToISODateTime(const char* inputDateTime, char* outputISODateTime) {
	struct tm timeinfo;
	memset(&timeinfo, 0, sizeof(struct tm));

	// Define the format of the input date string
	const char* inputFormat = "%a, %d %b %Y %H:%M:%S %Z";

	// Parse the input date string
	if (strptime(inputDateTime, inputFormat, &timeinfo) == NULL) {
		fprintf(stderr, "Error parsing date string.\n");
		return;
	}

	// Convert the parsed time to time_t
	time_t epochTime = mktime(&timeinfo);

	// Format the time in ISO format
	strftime(outputISODateTime, 128, "%Y-%m-%dT%H:%M:%SZ", gmtime(&epochTime));
}

void unescapeHtml(char* str) {
	char* input = str;
	char* output = str;

	while (*input) {
		if (strncmp(input, "&amp;", 5) == 0) {
			*output = '&';
			input += 5;
		} else if (strncmp(input, "&lt;", 4) == 0) {
			*output = '<';
			input += 4;
		} else if (strncmp(input, "&gt;", 4) == 0) {
			*output = '>';
			input += 4;
		} else if (strncmp(input, "&quot;", 6) == 0) {
			*output = '"';
			input += 6;
		} else if (strncmp(input, "&apos;", 6) == 0) {
			*output = '\'';
			input += 6;
		} else if (strncmp(input, "%28", 3) == 0) {
			*output = '(';
			input += 4;
		} else if (strncmp(input, "%29", 3) == 0) {
			*output = ')';
			input += 4;
		} else {
			*output = *input;
			input++;
		}
		output++;
	}
	*output = '\0'; // Null-terminate the output string.
}
