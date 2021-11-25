#ifndef __IP_HELPER_H__
#define __IP_HELPER_H__

#include <linux/ip.h>

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

#endif