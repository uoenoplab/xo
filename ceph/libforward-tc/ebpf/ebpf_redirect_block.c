#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <string.h>

#define truncated(p, end)	!!((void *)(p + 1) > end)
#define DROP 1
#define REDIRECT 2
#define PASS 3

struct flow_key 
{
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
};

struct  map_value 
{
	__u32 new_src_ip;
	__u32 new_dst_ip;
	unsigned char new_src_mac[ETH_ALEN];
	unsigned char new_dst_mac[ETH_ALEN];
	__u16 new_sport;
	__u16 new_dport;
	__u8 block;
	__u8 redirect;
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);   
	__type(key, struct flow_key);
	__type(value, struct map_value);
	__uint(max_entries, 2048);
} map SEC(".maps");

static inline __u16 update_ip_checksum(struct iphdr *ip)
{
	__u32 csum = 0;
	__u16 *hdr_words= (__u16 *)ip;

	#pragma unroll
	for (int i = 0; i < sizeof(*ip) / sizeof(__u16); i++)
		csum = csum + hdr_words[i];

	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);

	return (__u16)~csum;
}

static void
dbg(int action, struct iphdr *ip, struct tcphdr *tcp)
{
	__u32 seq = bpf_ntohl(tcp->seq);

	if (action == DROP)
	{
		bpf_trace_printk("Dropping: seqno %u", 19, seq);
	}
	if (action == REDIRECT)
	{
		bpf_trace_printk("Redirecting: seqno %u", 22, seq);
	}
	if (action == PASS)
	{
		bpf_trace_printk("Passing: seqno %u", 18, seq);
	}
}

static __always_inline
void update_checksum(__u16 *csum, __u32 old_val, __u32 new_val)
{
	__u32 new_csum_value;
	__u32 new_csum_comp;
	__u32 undo;

	undo = ~(*csum) + ~old_val;
	new_csum_value = undo + (undo < ~old_val) + new_val;
	new_csum_comp = new_csum_value + (new_csum_value < new_val);
	new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);
	new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);
	*csum = (__u16)~new_csum_comp;
}

SEC("classifier") int
handle_packet(struct __sk_buff *skb)
{
	/* Extract packet info */
	struct ethhdr *eth;
	struct iphdr *ip;
	struct tcphdr *tcp;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
    
	eth = (struct ethhdr *)data;
	if (truncated(eth, data_end))
		return TC_ACT_PIPE;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_PIPE;

	ip = (struct iphdr *)(data + sizeof(*eth));
	if (truncated(ip, data_end))
		return TC_ACT_PIPE;
	if (ip->protocol != IPPROTO_TCP)
		return TC_ACT_PIPE;

	tcp = (struct tcphdr *)((void *)ip + (ip->ihl << 2));
	if (truncated(tcp, data_end))
		return TC_ACT_PIPE;
 
	/* Construct the key */
	struct flow_key flow;
	flow.src_ip = ip->saddr;
	flow.dst_ip = ip->daddr;
	flow.src_port = tcp->source;
	flow.dst_port = tcp->dest;
       
	/* Check the blocking map */
	struct map_value *value;
	value = bpf_map_lookup_elem(&map, &flow);
	if (value)
	{
		if (value->block)
		{
			//dbg(DROP, ip, tcp);
			return TC_ACT_SHOT;
		}
		else //if (value->redirect)
		{
			//dbg(REDIRECT, ip, tcp);
			ip->daddr = value->new_dst_ip;
			ip->saddr = value->new_src_ip;
			ip->id = bpf_htons(0);
			ip->ttl = 75;

			tcp->dest = value->new_dport;
			tcp->source = value->new_sport;

			memcpy(eth->h_source, value->new_src_mac, ETH_ALEN);
			memcpy(eth->h_dest, value->new_dst_mac, ETH_ALEN);

			ip->check = 0;
			ip->check = update_ip_checksum(ip);

			__u16 *tcp_checksum = &(tcp->check);
			update_checksum(tcp_checksum, flow.dst_ip, value->new_dst_ip);
			update_checksum(tcp_checksum, flow.src_ip, value->new_src_ip);
			update_checksum(tcp_checksum, flow.src_port, value->new_sport);
			update_checksum(tcp_checksum, flow.dst_port, value->new_dport);

			bpf_redirect(skb->ifindex, 0);
			return TC_ACT_REDIRECT;
		}
		//else
		//	return TC_ACT_PIPE;
	}
	return TC_ACT_PIPE;
}

char _license[] SEC("license") = "GPL";
