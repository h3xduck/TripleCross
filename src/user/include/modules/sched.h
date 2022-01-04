#ifndef __MOD_SCHED_H
#define __MOD_SCHED_H

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "common.h"
#include "xdp_filter.skel.h"

//TODO RESOLVE THE FACT THAT THESE ARE NOT COMPILED WITH REFERENCE TO XDP_FILTER_BPF
//COMPLETE CONFIG
//CHECK EVERYTHING STILL WORKS

//Connections
int attach_handle_sched_process_exec(struct xdp_filter_bpf *skel){
    skel->links.handle_sched_process_exec = bpf_program__attach(skel->progs.handle_sched_process_exec);
	return libbpf_get_error(skel->links.handle_sched_process_exec);
}

int attach_sched_all(struct xdp_filter_bpf *skel){
    return attach_handle_sched_process_exec(skel);
}


//Disconnections
int detach_handle_sched_process_exec(struct xdp_filter_bpf *skel){
    int err = detach_link_generic(skel->links.handle_sched_process_exec);
    if(err<0){
        fprintf(stderr, "Failed to detach sched link\n");
        return -1;
    }
    return 0;
}

int detach_sched_all(struct xdp_filter_bpf *skel){
    return detach_handle_sched_process_exec(skel);
}


#endif