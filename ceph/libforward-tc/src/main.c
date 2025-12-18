#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>

#include "forward.h"
#include "ebpf_forward.h"

int main(int argc, char **argv)
{
	if (argc != 4) {
		fprintf(stderr, "Usage: %s [device] [ingress class parent] [egress class parent]\n", argv[0]);
		exit(1);
	}

	assert(init_forward(argv[1], argv[2], argv[3]) >= 0);

	apply_redirection_ebpf_str("192.168.11.12", "192.168.11.110",
			8888, 8889,
			"192.168.11.12", "94:6d:ae:8c:87:ac", "192.168.11.80", "a0:88:c2:46:bd:7e",
			9000, 9001, false);
//	remove_redirection_ebpf_str("192.168.11.12", "192.168.11.110", 8888, 8889);
//	apply_redirection_str("192.168.11.164", "3c:fd:fe:e5:a4:d0", "192.168.11.131", "00:15:4d:13:70:b5",
//			9000, 9001,
//			"192.168.11.131", "00:15:4d:13:70:b5", "192.168.11.163", "3c:fd:fe:e5:ba:10",
//			8888, 8889, false);


	return 0;
}
