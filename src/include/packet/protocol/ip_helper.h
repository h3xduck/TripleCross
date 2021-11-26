#ifndef __IP_HELPER_H__
#define __IP_HELPER_H__

#include <linux/ip.h>
#include <linux/types.h>

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

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
        sum +=htons((unsigned char)*addr);
    }
            
    while (sum>>16){
        sum = (sum & 0xffff) + (sum >> 16);
    }

    checksum = ~sum;
    return checksum;
}


static __always_inline uint16_t csum_fold_helper(uint32_t csum)
{
    bpf_printk("csumA: %u\n", csum & 0xffff);
    bpf_printk("csumB: %u\n", csum >> 16);
    bpf_printk("csumA+B: %u\n", (csum & 0xffff) + (csum >> 16));
    bpf_printk("csumNEG(A+B): %u\n", ~((csum & 0xffff) + (csum >> 16)));
    #pragma unroll
    for (int ii = 0; ii < 4; ii++) {
    if (csum >> 16)
        csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}
/**
* IP checksum calculation.
* Following RFC 1071, using BPFs.*
*/
static __always_inline void ipv4_csum(void *data_start, int data_size, uint32_t *csum)
{
    bpf_printk("csum: %u\n", *csum);
	*csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
	bpf_printk("csum: %u\n", *csum);
    *csum = csum_fold_helper(*csum);
    bpf_printk("csum: %u\n", *csum);
}

#endif