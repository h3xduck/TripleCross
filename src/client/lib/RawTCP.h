#ifndef HEADER_RAWTCP_LIB
#define HEADER_RAWTCP_LIB

#include <stdlib.h>

//Packet_t and stream_t structures
typedef struct packet_t{
    struct iphdr *ipheader;
    struct tcphdr *tcpheader;
    char *payload;
    int payload_length;
    char* packet;
}packet_t;

typedef struct stream_t{
    packet_t* packet_stream;
    int stream_length;
}stream_t;

typedef enum{
    TYPE_TCP_SEQ_RAW,
    TYPE_TCP_ACK_RAW
}stream_inject_type_t;

//PacketForger headers
packet_t build_standard_packet(
    u_int16_t source_port,
    u_int16_t destination_port,
    const char* source_ip_address,
    const char* destination_ip_address,
    u_int32_t packet_length,
    char* payload
    );

stream_t build_standard_packet_stream_empty_payload(
    int stream_length,
    u_int16_t source_port,
    u_int16_t destination_port,
    const char* source_ip_address,
    const char* destination_ip_address
    );

stream_t stream_inject(stream_t stream, stream_inject_type_t type, char* payload, int payload_length);

int packet_destroy(packet_t packet);

void stream_destroy(stream_t stream);

int set_TCP_flags(packet_t packet, int hex_flags);

int set_TCP_seq_num(packet_t packet, u_int32_t bytes);

//SocketManager headers
int rawsocket_send(packet_t packet);

packet_t rawsocket_sniff();

packet_t rawsocket_sniff_pattern(char* payload_pattern);

#endif