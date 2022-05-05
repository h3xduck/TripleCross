#ifndef __PROTOCOL_H
#define __PROTOCOL_H

//V1

//Value added to K3 to define command to send
#define CC_PROT_K3_TOTAL_DEFINED_KEYS_V1 1
#define CC_PROT_K3_ENCRYPTED_SHELL_TRIGGER_V1 0x00




//V2
struct trigger_t {
    unsigned char xor_key;
    unsigned int ip;
    short unsigned int port;
    unsigned char pad1;
    short unsigned int pad2;
    short unsigned int crc;
};



#endif