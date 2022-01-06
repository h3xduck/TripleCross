#ifndef __IP_HELPER_H__
#define __IP_HELPER_H__

/*#include <linux/ip.h>
#include <linux/types.h>

#include <linux/bpf.h>*/
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "newnewvmlinux.h"

/**
 * IP checksum calculation.
 * Following RFC 1071.
 * In essence 1's complement of 16-bit groups.
 * Taken from my own library https://github.com/h3xduck/RawTCP_Lib/blob/master/src/packet.c
 */ 
static __always_inline unsigned short checksum(unsigned short *addr, int nbytes){
    long sum = 0;
    unsigned short checksum;
    while(nbytes>1){
        sum += (unsigned short) *addr++;
        nbytes -= 2;
    }
    if(nbytes>0){
        sum +=bpf_htons((unsigned char)*addr);
    }
        
    while (sum>>16){
        sum = (sum & 0xffff) + (sum >> 16);
    }

    checksum = ~sum;
    return checksum;
}


static __always_inline __u16 csum_fold_helper(__u32 csum)
{
    //return ~((csum & 0xffff) + (csum >> 16));
    //The following solves some errors where the last summatory overflows
    #pragma unroll
    for (int i = 0; i < 4; i ++) {
        if (csum >> 16){
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    return ~csum;                 
}
/**
* IP checksum calculation.
* Following RFC 1071, using BPFs.*
*/
static __always_inline void ipv4_csum(void *data_start, int data_size, __u32 *csum)
{
    //WITH EBPF HELPERS
    bpf_printk("csum: %u for data_start %u, data_size %i\n", *csum, data_start, data_size);
	
    /*unsigned char* p = (unsigned char*) data_start;
    for(int ii = 0; ii<20; ii++){
        bpf_printk("B%i: %x\n", ii, p[ii]);
    }*/

    *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
    *csum = csum_fold_helper(*csum);
}

#endif