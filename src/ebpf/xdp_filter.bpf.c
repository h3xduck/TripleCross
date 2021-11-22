//#include "newvmlinux.h"
#include <linux/ip.h>
#include <linux/types.h>
#include <unistd.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <linux/unistd.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../user/xdp_filter.h"
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>


char LICENSE[] SEC("license") = "Dual BSD/GPL";

//BPF map
/*struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, char[5]);
} exec_start SEC(".maps");*/

//Ring buffer
/*struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");*/

//Ethernet frame struct
struct eth_hdr {
	unsigned char   h_dest[ETH_ALEN];
	unsigned char   h_source[ETH_ALEN];
	unsigned short  h_proto;
};

SEC("xdp_prog")
int xdp_receive(struct xdp_md *ctx)
{
    bpf_printk("BPF triggered\n");
    
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    char match_pattern[] = "test";
    unsigned int payload_size, i;
    struct ethhdr *eth = data;
    unsigned char *payload;
    struct udphdr *udp;
    struct iphdr *ip;
    
	/*struct event *rb_event;

	Reserve a ring buffer event from BPF ringbuf to be filled later*/
	/*rb_event = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
	if (!rb_event)
		return 0;*/

    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    udp = (void *)ip + sizeof(*ip);
    if ((void *)udp + sizeof(*udp) > data_end)
        return XDP_PASS;

    if (udp->dest != ntohs(5005))
        return XDP_PASS;

    payload_size = ntohs(udp->len) - sizeof(*udp);
    // Here we use "size - 1" to account for the final '\0' in "test".
    // This '\0' may or may not be in your payload, adjust if necessary.
    if (payload_size != sizeof(match_pattern) - 1) 
        return XDP_PASS;

    // Point to start of payload.
    payload = (unsigned char *)udp + sizeof(*udp);
    if ((void *)payload + payload_size > data_end)
        return XDP_PASS;

	
    // Compare each byte, exit if a difference is found.
    for (i = 0; i < payload_size; i++)
        if (payload[i] != match_pattern[i])
            return XDP_PASS;

    bpf_printk("BPF finished\n ");
    /*if(!payload){
		bpf_probe_read_str(&rb_event->payload, sizeof(rb_event->payload), (void *)payload);
		bpf_ringbuf_submit(rb_event, 0);	
	}else{
		//Submit it to user-space for post-processing
		bpf_probe_read_str(&rb_event->payload, sizeof(rb_event->payload), (void*)0);
		bpf_ringbuf_submit(rb_event, 0);
	}*/
	
	// Same payload as expected one received, drop.
    return XDP_DROP;
}




