#ifndef __MAP_DEFS_H
#define __MAP_DEFS_H

#define RB_EVENT_MAX_MESSAGE_SIZE 512

// Ring buffer for kernel->user communication
typedef enum {
    INFO,
    DEBUG,
    EXIT,
    ERROR
} event_type_t;

struct rb_event {
	int pid;
    char message[RB_EVENT_MAX_MESSAGE_SIZE];
    int code;
    event_type_t event_type;
};

//sched_process_exec tracepoint contents
//now included in vmlinux
/*struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};
struct trace_event_raw_sched_process_exec {
	struct trace_entry ent;
	unsigned int __data_loc_filename;
	int pid;
	int old_pid;
	char __data[0];
};*/

#endif
