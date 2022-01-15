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
    //bpf_printk("PID: %u, FS:%u\n", pid, fd);
    return 0;
}

/**
 * @brief Receives read event and stores the parameters into internal map
 * 
 */
SEC("kprobe/ksys_read") 
int kprobe_ksys_read(struct pt_regs *ctx) { 
    struct pt_regs *rctx = ctx; 
    if (!rctx) return 0; 
    int fd = (int) PT_REGS_PARM1(ctx); 
    char *buf = (char *) PT_REGS_PARM2(ctx); 
    return handle_sys_read(ctx, fd, buf); 
} 

/**
 * @brief Called AFTER the ksys_read call, checks the internal
 * map for the tgid+pid used and extracts the parameters.
 * Uses the user-space buffer reference for overwritting the returned
 * values. 
 * 
 */
SEC("kretprobe/vfs_read")
int kretprobe_vfs_read(struct pt_regs *ctx){
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct fs_open_data *data = (struct fs_open_data*) bpf_map_lookup_elem(&fs_open, &pid_tgid);
    if (data!=NULL){
        //Not found
        return -1;
    }

    //Overwritting a byte of the buffer
    char *buf = data->buf;
    char *msg = "OOOOOOOOOOOOO";
    bpf_printk("Overwritting at pid %u\n", data->pid);
    //int err = bpf_probe_write_user((void*)buf, (void*)msg, (__u32)1);
    

    return 0;
}

#endif