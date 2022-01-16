#ifndef __TCP_HELPER_H__
#define __TCP_HELPER_H__

/*#include <linux/tcp.h>
#include <linux/ip.h>*/
#include "headervmlinux.h"

static __always_inline int get_tcp_src_port(struct tcphdr *tcp){
    return bpf_ntohs(tcp->source);
}

static __always_inline int get_tcp_dest_port(struct tcphdr *tcp){
    return bpf_ntohs(tcp->dest);
}

/**
 * TCP checksum calculation.
 * Following RFC 1071.
 * In essence 1's complement of 16-bit groups.
 * Taken from my own library https://github.com/h3xduck/RawTCP_Lib/blob/master/src/segment.c
 */ 
static __always_inline unsigned short tcp_checksum(unsigned short *addr, int nbytes){
    long sum = 0;
    unsigned short checksum;
    while(nbytes>1){
        sum += (unsigned short) *addr++;
        nbytes -= 2;
    }
    if(nbytes>0){
        sum += bpf_htons((unsigned char)*addr);
    }
            
    while (sum>>16){
        sum = (sum & 0xffff) + (sum >> 16);
    }

    checksum = ~sum;
    return checksum;
}

#endif