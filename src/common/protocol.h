#ifndef __PROTOCOL_H
#define __PROTOCOL_H

struct trigger_t {
    unsigned char xor_key;
    unsigned int ip;
    short unsigned int port;
    unsigned char pad1;
    short unsigned int pad2;
    short unsigned int crc;
};


#endif