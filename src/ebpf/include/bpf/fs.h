#ifndef __FS_H
#define __FS_H

#include "newnewvmlinux.h"
/*#include <stdio.h>
#include <linux/types.h>
#include <unistd.h>
#include <string.h>
#include <linux/ptrace.h>
#include <linux/stat.h>*/

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../../../common/constants.h"
#include "../../../common/map_defs.h"
#include "../data/ring_buffer.h"
#include "bpf_defs.h"

#define FS_MAX_SEGMENT_LENGTH 32


SEC("kprobe/vfs_open") 
int kprobe__64_sys_read(struct pt_regs *ctx){
    //struct path *path = (struct path *)PT_REGS_PARM1(ctx);
    return 0;//fa_access_path(path);
}


#endif