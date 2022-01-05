#ifndef __FS_H
#define __FS_H

#include <stdio.h>
#include <linux/types.h>
#include <unistd.h>
#include <string.h>
#include <linux/ptrace.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../../../common/constants.h"
#include "../../../common/map_defs.h"
#include "../data/ring_buffer.h"
#include "bpf_defs.h"

static __always_inline int kprobe__sys_read(struct pt_regs *ctx ,int fd ,char * buf){
    bpf_printk("Read a file");
    return 0;
}

SEC("kprobe/compat_sys_read") 
int __attribute__((always_inline)) kprobe__64_compat_sys_read(struct pt_regs *ctx) {
    struct pt_regs *rctx = ctx; if (!rctx) return 0; 
    int fd = (int) PT_REGS_PARM1(ctx); 
    char * buf = (char *) PT_REGS_PARM2(ctx); 
    return kprobe__sys_read(ctx ,fd ,buf); 
}

SEC("kprobe/sys_read") 
int kprobe__64_sys_read(struct pt_regs *ctx) { 
    struct pt_regs *rctx = ctx; 
    if (!rctx) return 0; 
    int fd = (int) PT_REGS_PARM1(ctx); 
    char * buf = (char *) PT_REGS_PARM2(ctx); 
    return kprobe__sys_read(ctx ,fd ,buf); 
} 


#endif