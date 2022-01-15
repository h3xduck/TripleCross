#ifndef __PACKET_MANAGER_H__
#define __PACKET_MANAGER_H__
/*#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/limits.h>*/
#include "headervmlinux.h"

/* BOUND CHECKING*/

static __always_inline int ethernet_header_bound_check(struct ethhdr *eth, void* data_end){
    if ((void *)eth + sizeof(struct ethhdr) > data_end){
        return -1;
    }
    return 0; //OK
}

static __always_inline int ip_header_bound_check(struct iphdr* ip, void* data_end){
    if ((void *)ip + sizeof(*ip) > data_end){
        return -1;
    }
    return 0; //OK
}

static __always_inline int tcp_header_bound_check(struct tcphdr* tcp, void* data_end){
    if ((void *)tcp + sizeof(*tcp) > data_end){
        return -1;
    }
    return 0; //OK
}

static __always_inline int tcp_payload_bound_check(char* payload, int payload_size, void* data_end){
    if ((void*)payload + payload_size > data_end){
        return -1;
    }
    return 0; //OK
}



/* UTILITIES */

static __always_inline int get_protocol(void* data){
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);
    switch(ip->protocol){
        case IPPROTO_TCP:
            return IPPROTO_TCP;
        case IPPROTO_UDP:
            return IPPROTO_UDP;
        default:
            return -1; //Unknown and not handled.
    }
}

static __always_inline unsigned char* get_payload(struct tcphdr *tcp){
    return (void *)tcp + tcp->doff*4;
}

#endif