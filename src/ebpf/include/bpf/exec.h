#ifndef __EXEC_H
#define __EXEC_H

#include "headervmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../../../common/constants.h"
#include "../../../common/map_common.h"
#include "defs.h"
#include "../utils/strings.h"


/**
 * >> cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_open/format
 */
struct sys_execve_enter_ctx {
    unsigned long long unused;
    int __syscall_nr;
    unsigned int padding;
    const char* const *argv;
    const char* filename;
    const char* const *envp;
};


SEC("tp/syscalls/sys_enter_execve")
int tp_sys_enter_execve(struct sys_execve_enter_ctx *ctx) {

}



#endif