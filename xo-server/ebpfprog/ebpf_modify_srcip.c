#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <string.h>

#define truncated(p, end)        !!((void *)(p + 1) > end)
#define DROP 1
#define REDIRECT 2
#define PASS 3
#define MOD 4

struct flow_key 
{
        __u32 src_ip;
        __u32 dst_ip;
        __u16 src_port;
        __u16 dst_port;
};

struct  map_value 
{
        __u8 block;
        __u8 redirect;
	__u8 modify_src_ip;
        __u32 new_src_ip;
        __u32 new_dst_ip;
        unsigned char new_src_mac[ETH_ALEN];
        unsigned char new_dst_mac[ETH_ALEN];
};

struct
{
        __uint(type, BPF_MAP_TYPE_HASH);   
        __type(key, struct flow_key);
        __type(value, struct map_value);
        __uint(max_entries, 4096);
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

        if (action == PASS)
        {
                bpf_trace_printk("Passing: seqno %u", 18, seq);
        }
	if (action == MOD)
	{
                bpf_trace_printk("Modify: seqno %u", 17, seq);
	}
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
		if (value->modify_src_ip)
		{
			//dbg(MOD, ip, tcp);
			__u32 old_saddr = ip->saddr;
			ip->saddr = value->new_src_ip;
			
			ip->check = 0;
			ip->check = update_ip_checksum(ip);
			
                        __u32 tcp_csum_offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check);
			bpf_l4_csum_replace(skb, tcp_csum_offset, old_saddr, ip->saddr, BPF_F_PSEUDO_HDR | sizeof(ip->saddr));

		}
        }
        return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
