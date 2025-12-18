#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include "forward.h"

int main(int argc, char **argv)
{
        char client_ip[20] = "192.168.11.51";
        char original_ip[20] = "192.168.11.53";
        char fake_ip[20] = "192.168.11.2";
        char client_mac[20] = "98:03:9b:85:f3:4e";
        char original_mac[20] = "98:03:9b:8c:19:f0";
        char fake_mac[20] = "ec:0d:9a:48:73:1e";

	bool blocking_disabled = false;
#ifdef TCSW
	bool hw_offload = false;
#endif /* TCSW */
#ifdef TCHW
	bool hw_offload = true;
#endif /* TCHW */

 	if (argc != 4) 
        {
  		fprintf(stderr,"Usage: %s [device] [ingress class parent] [egress class parent]\n", argv[0]); 
  		exit(1);
  	}
  	assert(init_forward(argv[1], argv[2], argv[3]) >= 0);

	int ret;
	ret = apply_redirection_str(
	                client_ip, 
	                original_ip, 
	                8888, 50000,
	
	                client_ip, original_mac, 
	                fake_ip, fake_mac,
		        8888, 50000, 
	                blocking_disabled, hw_offload);
#ifdef TCSW
	if (ret)
		perror("tcsw apply_redirection_str failed\n");
	else
		printf("tcsw redirection rule inserted\n");
#endif
#ifdef TCHW
	if (ret)
		perror("tchw apply_redirection_str failed\n");
	else
		printf("tchw redirection rule inserted\n");
#endif

//	if (argc != 4) {
//		fprintf(stderr, "Usage: %s [device] [ingress class parent] [egress class parent]\n", argv[0]);
//		exit(1);
//	}
//
//	assert(init_forward(argv[1], argv[2], argv[3]) >= 0);

//	apply_redirection_str("192.168.11.163", "3c:fd:fe:e5:ba:10", "192.168.11.131", "00:15:4d:13:70:b5",
//			8888, 8889,
//			"192.168.11.131", "00:15:4d:13:70:b5", "192.168.11.164", "3c:fd:fe:e5:a4:d0",
//			9000, 9001, false);
//	apply_redirection_str("192.168.11.164", "3c:fd:fe:e5:a4:d0", "192.168.11.131", "00:15:4d:13:70:b5",
//			9000, 9001,
//			"192.168.11.131", "00:15:4d:13:70:b5", "192.168.11.163", "3c:fd:fe:e5:ba:10",
//			8888, 8889, false);



//	apply_redirection_str("192.168.11.163", "3c:fd:fe:e5:ba:10", "192.168.11.131", "00:15:4d:13:70:b5",
//			8888, 8889,
//			"192.168.11.131", "00:15:4d:13:70:b5", "192.168.11.164", "3c:fd:fe:e5:a4:d0",
//			8888, 8889, false);

//	apply_redirection_str("192.168.11.164", "192.168.11.131",
//			8888, 8889,
//			"192.168.11.131", "3c:fd:fe:e5:a4:d0", "192.168.11.163", "3c:fd:fe:e5:ba:10",
//			8888, 8889, true, false);

//	remove_redirection_str("192.168.11.164", "192.168.11.131",
//			      8888, 8889);

//	remove_redirection_str("192.168.11.131", "00:15:4d:13:70:b5", "192.168.11.164", "3c:fd:fe:e5:a4:d0",
//			      (uint16_t)8889, (uint16_t)8888);
//
//	remove_redirection_str("192.168.11.131", "00:15:4d:13:70:b5", "192.168.11.164", "3c:fd:fe:e5:a4:d0",
//			      (uint16_t)8880, (uint16_t)8881);
	return 0;
}
