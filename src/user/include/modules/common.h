#ifndef __MODULE_COMMON_H
#define __MODULE_COMMON_H

#include <linux/bpf.h>
#include <bpf/libbpf.h>

int detach_link_generic(struct bpf_link *link){
    int ret = bpf_link__destroy(link);
    if(ret!=0){
        return -1;
    }
    return 0;
}

#endif