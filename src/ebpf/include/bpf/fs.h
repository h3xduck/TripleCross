#ifndef __FS_H
#define __FS_H

#include <stdio.h>
#include <linux/types.h>
#include <unistd.h>
#include <string.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../common/constants.h"
#include "../common/map_defs.h"

#define RING_BUFFER_MAX_ELEMS 256
//Ring buffer - For communication ebpf -> userspace
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RING_BUFFER_MAX_ELEMS * 1024); //Multiple struct rb_event(s) must fit here
} rb_comm SEC(".maps");

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
int handle_exec(struct trace_event_raw_sched_process_exec *ctx){
	struct task_struct *task;
	unsigned fname_off;
	struct rb_event *e;
	pid_t pid;
	int ts;

	pid = bpf_get_current_pid_tgid() >> 32;
	ts = bpf_ktime_get_ns();

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb_comm, sizeof(*e), 0);
	if (!e){
		return 0;
	}

	e->pid = pid;
	e->event_type = INFO;
	e->code = 0;
	
	char* message = "HOLA\0";
	bpf_probe_read_str(&e->message, sizeof(message), message);

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}


#endif

