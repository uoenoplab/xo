#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <time.h>
#include <assert.h>
#include <sched.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_ether.h>

struct flow_key 
{
        __u32 src_ip;
        __u32 dst_ip; 
        __u16 src_port; 
        __u16 dst_port;
};
struct map_value 
{
        __u8 block;
        __u8 redirect;
        __u32 new_dst_ip;
        unsigned char new_src_mac[ETH_ALEN];
        unsigned char new_dst_mac[ETH_ALEN];
};

void parse_mac(const char* mac_str, unsigned char* mac)
{// used in ebpf rule insertion
        int values[6];
        if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x", 
                                &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]) == 6)
                for (int i = 0; i < 6; ++i)
                        mac[i] = (uint8_t) values[i];
        else
        {
                printf("sscanf in parse_mac error\n");
                exit(0);
        }
}

int main()
{
//	char client_ip[20] = "192.168.11.51";
//	char original_ip[20] = "192.168.11.53";
//	char fake_ip[20] = "192.168.11.2";
//	char client_mac[20] = "98:03:9b:85:f3:4e";
//	char original_mac[20] = "98:03:9b:8c:19:f0";
//	char fake_mac[20] = "ec:0d:9a:48:73:1e";	

	char client_ip[20] = "10.10.10.1";
	char original_ip[20] = "10.10.10.2";
	char fake_ip[20] = "10.10.10.1";
	char client_mac[20] = "64:9d:99:b1:91:50";
	char original_mac[20] = "98:03:9b:8c:19:f0";
	char fake_mac[20] = "64:9d:99:b1:91:51";	
#ifdef EBPF
        /* open ebpf map */
	int map_fd = -1;
	map_fd = bpf_obj_get("/sys/fs/bpf/ebpf_redirect_block/map");
        if (map_fd < 0) 
		printf("Failed to open BPF maps\n");

	/* prepare for ebpf rule */
	struct flow_key key = {}; 
	struct map_value value = {};

	//ebpf needs network byte order
	key.src_ip = inet_addr(client_ip);
	key.dst_ip = inet_addr(original_ip);
	key.src_port = htons(1234);
	key.dst_port = htons(1234);
	
	value.block = 0;
	value.redirect = 1;
	value.new_dst_ip = inet_addr(fake_ip);
	unsigned char mac[6];
	parse_mac(original_mac, mac);
	memcpy(value.new_src_mac, mac, sizeof(mac));
	parse_mac(fake_mac, mac);
	memcpy(value.new_dst_mac, mac, sizeof(mac));
	
	int ret;
	ret = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
	if (ret)
		printf("error bpf_map_update_elem redirect\n");
	else
		printf("bpf redirection rule inserted\n");
#endif /* EBPF */
}
