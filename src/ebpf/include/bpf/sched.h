#ifndef __SCHED_H
#define __SCHED_H

#/*include <stdio.h>
#include <linux/types.h>
#include <unistd.h>
#include <string.h>

#include <linux/bpf.h>*/
#include "headervmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../../../common/constants.h"
#include "../../../common/map_common.h"
#include "../data/ring_buffer.h"

//BPF map
/*struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, char[5]);
} exec_start SEC(".maps");*/


/**
 * @brief A kthread is started in the kernel (a new program)
 * @ref https://elixir.bootlin.com/linux/latest/source/include/trace/events/sched.h#L397
 */
SEC("tp/sched/sched_process_exec")
int handle_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx){
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	char message[] = "PROCESS ACTIVATED";

	//Just deactivated for now, but working
	/*if(ring_buffer_send(&rb_comm, pid, INFO, 0, message, sizeof(message))<0){
		bpf_printk("ERROR printing in RB_COMM at fs module");
	}*/

	return 0;
}


#endif

