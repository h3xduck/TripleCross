#ifndef __PACKET_MANAGER_H__
#define __PACKET_MANAGER_H__
#include <linux/bpf.h>
#include <linux/if_ether.h>

static __always_inline int ethernet_header_bound_check(struct ethhdr *eth, void* data_end){
    if ((void *)eth + sizeof(struct ethhdr) > data_end){
        return -1;
    }
    return 0; //OK
}

#endif