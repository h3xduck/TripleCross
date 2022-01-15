#ifndef __BPF_MAP_DEFS_H
#define __BPF_MAP_DEFS_H

#include "headervmlinux.h"

//File system
struct fs_open_data{
	char* buf;
	int fd;
	__u32 pid;
};

struct fs_open{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024*sizeof(struct fs_open_data));
	__type(key, __u64); //thread group id(MSB) + pid (LSB)
	__type(value, struct fs_open_data);
} fs_open SEC(".maps");

#endif