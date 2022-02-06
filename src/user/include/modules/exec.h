#ifndef __MOD_EXEC_H
#define __MOD_EXEC_H

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "common.h"
#include "kit.skel.h"

//Connections
int attach_tp_sys_enter_execve(struct kit_bpf *skel){
    skel->links.tp_sys_enter_execve = bpf_program__attach(skel->progs.tp_sys_enter_execve);
	return libbpf_get_error(skel->links.tp_sys_enter_execve);
}

int attach_exec_all(struct kit_bpf *skel){
    return attach_tp_sys_enter_execve(skel);
}


int detach_tp_sys_enter_execve(struct kit_bpf *skel){
    int err = detach_link_generic(skel->links.tp_sys_enter_execve);
    if(err<0){
        fprintf(stderr, "Failed to detach fs link\n");
        return -1;
    }
    return 0;
}

int detach_exec_all(struct kit_bpf *skel){
    return detach_tp_sys_enter_execve(skel);
}

#endif