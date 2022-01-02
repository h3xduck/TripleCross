#ifndef __MOD_SCHED_H
#define __MOD_SCHED_H

#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include "xdp_filter.skel.h"

//Connections
int attach_handle_sched_process_exec(struct xdp_filter_bpf *skel){
    skel->links.handle_sched_process_exec = bpf_program__attach(skel->progs.handle_sched_process_exec);
	return libbpf_get_error(skel->links.handle_sched_process_exec);
}

int attach_sched_all(struct xdp_filter_bpf *skel){
    return attach_handle_sched_process_exec(skel);
}


//Disconnections
int detach_link_generic(struct bpf_link *link){
    int ret = bpf_link__destroy(link);
    if(ret!=0){
        return -1;
    }
    return 0;
}
int detach_sched_all(struct xdp_filter_bpf *skel){
    return detach_link_generic(skel->links.handle_sched_process_exec);
}


#endif