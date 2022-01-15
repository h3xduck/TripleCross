#ifndef __FS_H
#define __FS_H

#include "headervmlinux.h"
/*#include <stdio.h>
#include <linux/types.h>
#include <unistd.h>
#include <string.h>
#include <linux/ptrace.h>
#include <linux/stat.h>*/

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../../../common/constants.h"
#include "../../../common/map_common.h"
#include "../data/ring_buffer.h"
#include "map_defs.h"
#include "../utils/strings.h"


static __always_inline int handle_sys_read(struct pt_regs *ctx, int fd, char* buf){
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    struct fs_open_data data = {
        .buf = buf,
        .fd = fd,
        .pid = pid
    };
    bpf_map_update_elem(&fs_open, &pid_tgid, &data, BPF_ANY);
    bpf_printk("PID: %u, FS:%u\n", pid, fd);
    return 0;
}

SEC("kprobe/ksys_read") 
int kprobe__64_sys_read(struct pt_regs *ctx) { 
    struct pt_regs *rctx = ctx; 
    if (!rctx) return 0; 
    int fd = (int) PT_REGS_PARM1(ctx); 
    char *buf = (char *) PT_REGS_PARM2(ctx); 
    return handle_sys_read(ctx, fd, buf); 
} 

#endif