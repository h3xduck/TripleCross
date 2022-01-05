#ifndef __MOD_FS_H
#define __MOD_FS_H

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "common.h"
#include "xdp_filter.skel.h"

//Connections
int attach_kprobe__64_compat_sys_read(struct xdp_filter_bpf *skel){
    skel->links.kprobe__64_compat_sys_read = bpf_program__attach(skel->progs.kprobe__64_compat_sys_read);
	return libbpf_get_error(skel->links.kprobe__64_compat_sys_read);
}

int attach_kprobe__64_sys_read(struct xdp_filter_bpf *skel){
    skel->links.kprobe__64_sys_read = bpf_program__attach(skel->progs.kprobe__64_sys_read);
	return libbpf_get_error(skel->links.kprobe__64_sys_read);
}

int attach_fs_all(struct xdp_filter_bpf *skel){
    return attach_kprobe__64_compat_sys_read(skel) |
        attach_kprobe__64_sys_read(skel);
}


//Disconnections
int detach_kprobe__64_compat_sys_read(struct xdp_filter_bpf *skel){
    int err = detach_link_generic(skel->links.kprobe__64_compat_sys_read);
    if(err<0){
        fprintf(stderr, "Failed to detach fs link\n");
        return -1;
    }
    return 0;
}

int detach_kprobe__64_sys_read(struct xdp_filter_bpf *skel){
    int err = detach_link_generic(skel->links.kprobe__64_sys_read);
    if(err<0){
        fprintf(stderr, "Failed to detach fs link\n");
        return -1;
    }
    return 0;
}

int detach_fs_all(struct xdp_filter_bpf *skel){
    return detach_kprobe__64_compat_sys_read(skel) ||
        detach_kprobe__64_sys_read(skel);
}

#endif