#ifndef __TCP_HELPER_H__
#define __TCP_HELPER_H__

#include <linux/tcp.h>
#include <linux/ip.h>


static __always_inline int get_tcp_src_port(struct tcphdr *tcp){
    return ntohs(tcp->source);
}

static __always_inline int get_tcp_dest_port(struct tcphdr *tcp){
    return ntohs(tcp->dest);
}

#endif