#include <iostream>
#include <random>
#include <chrono>
#include <cassert>
#include <cstring>
#include <sys/ioctl.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <linux/if.h>

#include <arpa/inet.h>

#include "forward.h"

struct flows {
	uint32_t *src_ip;
	uint32_t *dst_ip;

	uint8_t *src_mac;
	uint8_t *dst_mac;

	uint16_t *sport;
	uint16_t *dport;

	uint32_t *new_src_ip;
	uint32_t *new_dst_ip;

	uint8_t *new_src_mac;
	uint8_t *new_dst_mac;

	uint16_t *new_sport;
	uint16_t *new_dport;

	bool *block;
};


int main(int argc, char *argv[])
{
	if (argc != 6) {
		fprintf(stderr, "Useage: %s [device name] [ingress or egress qdisc parent] [in/out] [no. of rules] [no. of warmups]\n", argv[0]);
		exit(1);
	}

	struct flows random_flows;
	unsigned long INSERT_FLOWS = atol(argv[4]);
	unsigned long WARMUP_FLOWS = atol(argv[5]);
	if (WARMUP_FLOWS == 0) WARMUP_FLOWS = 1;
	unsigned long MAX_FLOWS = INSERT_FLOWS + WARMUP_FLOWS;

	int direction;
	if (strcmp(argv[3], "in") == 0)
		direction = 1;
	else
		direction = 0;

	struct ifreq interface_request;
	memcpy(interface_request.ifr_name, argv[1], strlen(argv[1])+1);
	interface_request.ifr_name[strlen(argv[1])] = 0;
	struct sockaddr_in my_ip;
	int fd;

	if ((fd = socket(AF_INET,SOCK_DGRAM, 0)) == -1) {
		fprintf(stderr, "fail to open simple socket: %s\n", strerror(errno));
		return -1;
	}


	/* resolve interface IP address */
	if (ioctl(fd, SIOCGIFADDR, &interface_request) == -1) {
		fprintf(stderr, "fail to request interface: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	memcpy(&my_ip, &interface_request.ifr_addr, sizeof(struct sockaddr_in));
        close(fd);

	/* setup RNG */
	std::random_device rd;
	std::mt19937 mt(rd());
	std::uniform_int_distribution<uint32_t> u32_rand(1, UINT32_MAX);
	std::uniform_int_distribution<uint16_t> u16_rand(1, UINT16_MAX);
	std::uniform_int_distribution<uint8_t> u8_rand(1, UINT8_MAX);

	/* filter attributes */
	random_flows.src_ip = (uint32_t*)calloc(MAX_FLOWS, sizeof(uint32_t));
	random_flows.dst_ip = (uint32_t*)calloc(MAX_FLOWS, sizeof(uint32_t));
	random_flows.src_mac = (uint8_t*)calloc(MAX_FLOWS * 8, sizeof(uint8_t));
	random_flows.dst_mac = (uint8_t*)calloc(MAX_FLOWS * 8, sizeof(uint8_t));
	random_flows.sport = (uint16_t*)calloc(MAX_FLOWS, sizeof(uint16_t));
	random_flows.dport = (uint16_t*)calloc(MAX_FLOWS, sizeof(uint16_t));

	random_flows.new_src_ip = (uint32_t*)calloc(MAX_FLOWS, sizeof(uint32_t));
	random_flows.new_dst_ip = (uint32_t*)calloc(MAX_FLOWS, sizeof(uint32_t));
	random_flows.new_src_mac = (uint8_t*)calloc(MAX_FLOWS * (unsigned long)8, sizeof(uint8_t));
	random_flows.new_dst_mac = (uint8_t*)calloc(MAX_FLOWS * (unsigned long)8, sizeof(uint8_t));
	random_flows.new_sport = (uint16_t*)calloc(MAX_FLOWS, sizeof(uint16_t));
	random_flows.new_dport = (uint16_t*)calloc(MAX_FLOWS, sizeof(uint16_t));

	/* init libforward-tc and random flows */
	init_forward(argv[1], argv[2], argv[3]);
	std::cout << "Initializing " << MAX_FLOWS << " rules..." << std::endl;
	for (unsigned long i = 0; i < MAX_FLOWS; i++) {
		if (direction == 1) {
			random_flows.src_ip[i] = u32_rand(mt);
			random_flows.dst_ip[i] = my_ip.sin_addr.s_addr;
		}
		else {
			random_flows.src_ip[i] = my_ip.sin_addr.s_addr;
			random_flows.dst_ip[i] = u32_rand(mt);
		}

		random_flows.sport[i] = u16_rand(mt);
		random_flows.dport[i] = u16_rand(mt);

		random_flows.new_src_ip[i] = u32_rand(mt);
		random_flows.new_dst_ip[i] = u32_rand(mt);

		random_flows.new_sport[i] = u16_rand(mt);
		random_flows.new_dport[i] = u16_rand(mt);

		for (int j = 0; j < 8; j++) {
			random_flows.src_mac[i * 8 + j] = u8_rand(mt);
			random_flows.dst_mac[i * 8 + j] = u8_rand(mt);

			random_flows.new_src_mac[i * 8 + j] = u8_rand(mt);
			random_flows.new_dst_mac[i * 8 + j] = u8_rand(mt);
		}
	}

	/* warmup by loading qdisc with flows */
	std::cout << "Begin warmup..." << std::endl;
	for (unsigned long i = 0; i < WARMUP_FLOWS; i++) {
		assert (apply_redirection(random_flows.src_ip[i], random_flows.dst_ip[i],
					  random_flows.sport[i], random_flows.dport[i],
					  random_flows.new_src_ip[i], &random_flows.new_src_mac[i * 8], random_flows.new_dst_ip[i], &random_flows.new_dst_mac[i * 8],
					  random_flows.new_sport[i], random_flows.new_dport[i], true, true) == 0);
		assert (apply_redirection(random_flows.src_ip[i], random_flows.dst_ip[i],
					  random_flows.sport[i], random_flows.dport[i],
					  random_flows.new_src_ip[i], &random_flows.new_src_mac[i * 8], random_flows.new_dst_ip[i], &random_flows.new_dst_mac[i * 8],
					  random_flows.new_sport[i], random_flows.new_dport[i], false, true) == 0);
	}

	/* remove a flow such that all actions are at least called once */
	if (WARMUP_FLOWS > 0) {
		remove_redirection(random_flows.src_ip[0], random_flows.dst_ip[0],
				   random_flows.sport[0], random_flows.dport[0]);
	}

	/* begin benchmark */
	std::chrono::steady_clock::time_point insert_start;
	std::chrono::steady_clock::time_point insert_end;
	std::chrono::steady_clock::time_point update_end;
	std::chrono::steady_clock::time_point remove_end;

	long insert_duration_ns = 0;
	long update_duration_ns = 0;
	long remove_duration_ns = 0;

	std::cout << "Begin insertion..." << std::endl;
	for (unsigned long i = WARMUP_FLOWS; i < MAX_FLOWS; i++) {
		/* insert drop rule */
		insert_start = std::chrono::steady_clock::now();
		assert (apply_redirection(random_flows.src_ip[i], random_flows.dst_ip[i],
					  random_flows.sport[i], random_flows.dport[i],
					  random_flows.new_src_ip[i], &random_flows.new_src_mac[i * 8], random_flows.new_dst_ip[i], &random_flows.new_dst_mac[i * 8],
					  random_flows.new_sport[i], random_flows.new_dport[i], true, true) == 0);
		insert_end = std::chrono::steady_clock::now();
		/* update drop rule to pedit rule */
		assert (apply_redirection(random_flows.src_ip[i], random_flows.dst_ip[i],
					  random_flows.sport[i], random_flows.dport[i],
					  random_flows.new_src_ip[i], &random_flows.new_src_mac[i * 8], random_flows.new_dst_ip[i], &random_flows.new_dst_mac[i * 8],
					  random_flows.new_sport[i], random_flows.new_dport[i], false, true) == 0);
		update_end = std::chrono::steady_clock::now();
		/* remove rule */
		remove_redirection(random_flows.src_ip[i], random_flows.dst_ip[i],
				   random_flows.sport[i], random_flows.dport[i]);
		remove_end = std::chrono::steady_clock::now();

		auto insert_ns = std::chrono::duration_cast<std::chrono::nanoseconds> (insert_end - insert_start).count();
		auto update_ns = std::chrono::duration_cast<std::chrono::nanoseconds> (update_end - insert_end).count();
		auto remove_ns = std::chrono::duration_cast<std::chrono::nanoseconds> (remove_end - update_end).count();

		std::cout << "Insertion " << i - WARMUP_FLOWS << ": " << insert_ns << "  ns" << std::endl;
		std::cout << "Update    " << i - WARMUP_FLOWS << ": " << update_ns << " ns" << std::endl;
		std::cout << "Remove    " << i - WARMUP_FLOWS << ": " << remove_ns << "  ns" << std::endl;

		insert_duration_ns += insert_ns;
		update_duration_ns += update_ns;
		remove_duration_ns += remove_ns;
	}

	std::cout << "Insertion rate: " << (double)INSERT_FLOWS / ((double)insert_duration_ns * 1e-9) << " rules/s, " << ((double)insert_duration_ns * 1e-6) / (double)INSERT_FLOWS << " ms/rule" << std::endl;
	std::cout << "Update rate   : " << (double)INSERT_FLOWS / ((double)update_duration_ns * 1e-9) << " rules/s, " << ((double)update_duration_ns * 1e-6) / (double)INSERT_FLOWS << " ms/rule" << std::endl;
	std::cout << "Removal rate  : " << (double)INSERT_FLOWS / ((double)remove_duration_ns * 1e-9) << " rules/s, " << ((double)remove_duration_ns * 1e-6) / (double)INSERT_FLOWS << " ms/rule" << std::endl;

	std::cout << "Cleanup..." << std::endl;
	/* remove warmup flows */
	for (unsigned long i = 1; i < WARMUP_FLOWS; i++) {
		remove_redirection(random_flows.src_ip[i], random_flows.dst_ip[i],
				   random_flows.sport[i], random_flows.dport[i]);
	}

	free(random_flows.src_ip);
	free(random_flows.dst_ip);

	free(random_flows.sport);
	free(random_flows.dport);

	free(random_flows.new_src_ip);
	free(random_flows.new_dst_ip);

	free(random_flows.new_sport);
	free(random_flows.new_dport);

	free(random_flows.src_mac);
	free(random_flows.dst_mac);

	free(random_flows.new_src_mac);
	free(random_flows.new_dst_mac);

	return 0;
}
