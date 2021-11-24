//#include "newvmlinux.h"
#include <unistd.h>
#include <stdbool.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <string.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../user/xdp_filter.h"
#include "../constants/constants.h"

#include "packet/packet_manager.h"
#include "packet/protocol/tcp_helper.h"
#include "common/common_utils.h"


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
    //bpf_printk("BPF triggered\n");
    
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    char match_pattern[] = SECRET_PACKET_PAYLOAD;
    int match_pattern_size = strlen(match_pattern);
    unsigned int payload_size;
    struct ethhdr *eth = data;
    char *payload;
    struct tcphdr *tcp;
    struct iphdr *ip;
    
    //Bound checking the packet before operating with it
    //Otherwise the bpf verifier will complain
    if(ethernet_header_bound_check(eth, data_end)<0){
        bpf_printk("Bound check fail A");
        return XDP_PASS;
    }

    ip = data + sizeof(*eth);
    if (ip_header_bound_check(ip, data_end)<0){
        bpf_printk("B");
        return XDP_PASS;   
    }

    if (get_protocol(data) != IPPROTO_TCP){
        bpf_printk("C");
        return XDP_PASS;
    }

    tcp = (void *)ip + sizeof(*ip);
    if (tcp_header_bound_check(tcp, data_end)){
        bpf_printk("D");
        return XDP_PASS;
    }

    if (get_tcp_dest_port(tcp) != SECRET_PACKET_DEST_PORT){
        bpf_printk("E %i\n", ntohs(tcp->dest));
        return XDP_PASS;
    }

    payload_size = ntohs(ip->tot_len) - (tcp->doff * 4) - (ip->ihl * 4);
    payload = (void *)tcp + tcp->doff*4;

    // We use "size - 1" to account for the final '\0'
    if (payload_size != sizeof(match_pattern) - 1) {
        bpf_printk("F");
        return XDP_PASS;
    }

    // Point to start of payload.
    if (tcp_payload_bound_check(payload, payload_size, data_end)){
        bpf_printk("G");
        return XDP_PASS;
    }

    bpf_printk("Received valid TCP packet with payload %s of size %i\n", payload, payload_size);
    // Compare each byte, exit if a difference is found.
    if(str_n_compare(payload, payload_size, match_pattern, match_pattern_size, payload_size)!=0){
        bpf_printk("H");
        return XDP_PASS;
    }

    bpf_printk("BPF finished\n ");
    payload[1] = 'b';
    /*if(!payload){
		bpf_probe_read_str(&rb_event->payload, sizeof(rb_event->payload), (void *)payload);
		bpf_ringbuf_submit(rb_event, 0);	
	}else{
		//Submit it to user-space for post-processing
		bpf_probe_read_str(&rb_event->payload, sizeof(rb_event->payload), (void*)0);
		bpf_ringbuf_submit(rb_event, 0);
	}*/
	
	// Same payload as secret one reeceived, pass it with modifications.
    return XDP_PASS;
}





