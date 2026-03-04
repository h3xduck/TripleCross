#ifndef __MODULE_COMMON_H
#define __MODULE_COMMON_H

#include <linux/bpf.h>
#include <bpf/libbpf.h>
#ifdef __BPF__  // 只有 clang 编译 eBPF 时才会定义这个宏
#include "headervmlinux.h"
#endif
int detach_link_generic(struct bpf_link *link){
    int ret = bpf_link__destroy(link);
    if(ret!=0){
        return -1;
    }
    return 0;
}

#endif