#ifndef __MAP_COMMON_H
#define __MAP_COMMON_H

// Ring buffer for kernel->user communication
#define RB_EVENT_MAX_MESSAGE_SIZE 512
typedef enum {
    INFO,
    DEBUG,
    EXIT,
    ERROR,
    VULN_SYSCALL
} event_type_t;

struct rb_event {
	int pid;
    char message[RB_EVENT_MAX_MESSAGE_SIZE];
    int code;
    __u64 syscall_address;
    __u64 process_stack_return_address;
    __u64 libc_main_address;
    __u64 libc_dlopen_mode_address;
    __u64 libc_malloc_address;
    __u64 got_address;
    __s32 got_offset;
    int relro_active;
    event_type_t event_type;
};

#endif
