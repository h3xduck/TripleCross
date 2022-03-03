#ifndef __BPF_INJECTION_H
#define __BPF_INJECTION_H


#include "headervmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../../../common/constants.h"

SEC("uprobe/execute_command")
int uprobe_execute_command(struct pt_regs *ctx){
    bpf_printk("UPROBE activated\n");
    return 0;
}

#endif