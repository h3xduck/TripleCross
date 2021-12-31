#ifndef __MOD_SCHED_H
#define __MOD_SCHED_H

#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include "xdp_filter.skel.h"

int attach_handle_sched_process_exec(struct xdp_filter_bpf *skel){
    skel->links.handle_sched_process_exec = bpf_program__attach(skel->progs.handle_sched_process_exec);
	return libbpf_get_error(skel->links.handle_sched_process_exec);
}

int attach_sched_all(struct xdp_filter_bpf *skel){
    return attach_handle_sched_process_exec(skel);
}


#endif