#ifndef __PROTOCOL_H
#define __PROTOCOL_H

//V1
#define CC_PROT_COMMAND_ENCRYPTED_SHELL 0

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