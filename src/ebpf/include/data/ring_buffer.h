#ifndef __RING_BUFFER_H
#define __RING_BUFFER_H

/*#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>*/
#include "headervmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../../../common/map_common.h"

#define RING_BUFFER_MAX_ELEMS 256

/**
 * @brief Ring buffer for general communication kernel->userspace
 * 
 */
struct ring_buffer {
__uint(type, BPF_MAP_TYPE_RINGBUF);
__uint(max_entries, RING_BUFFER_MAX_ELEMS * 1024); //Multiple struct rb_event(s) must fit here
};
struct ring_buffer rb_comm SEC(".maps");

/**
 * @brief Sends an event into the specified ring kernel buffer
 * 
 * @return 0 if ok, -1 if error
 */
static __always_inline int ring_buffer_send(struct ring_buffer *rb, int pid, event_type_t event_type, int code, char* message, __u32 message_len){
    struct rb_event *event = (struct rb_event*) bpf_ringbuf_reserve(rb, sizeof(struct rb_event), 0);
    if(!event){
        return -1;
    }

    event->code = code;
    event->event_type = event_type;
    event->pid = pid;
    bpf_probe_read_kernel_str(&event->message, message_len, message);

	bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * @brief Sends an event indicating a vulnerable syscall injection into the specified ring kernel buffer 
 * 
 * @return 0 if ok, -1 if error
 */
static __always_inline int ring_buffer_send_vuln_sys(struct ring_buffer *rb, int pid, __u64 syscall_address, __u64 process_stack_return_address, u64 libc_main_address, u64 libc_dlopen_mode_address, __u64 libc_malloc_address, __u64 got_address, __s32 got_offset, int relro_active){
    struct rb_event *event = (struct rb_event*) bpf_ringbuf_reserve(rb, sizeof(struct rb_event), 0);
    if(!event){
        return -1;
    }

    event->event_type = VULN_SYSCALL;
    event->pid = pid;
    event->libc_dlopen_mode_address = libc_dlopen_mode_address;
    event->libc_main_address = libc_main_address;
    event->libc_malloc_address = libc_malloc_address;
    event->process_stack_return_address = process_stack_return_address;
    event->syscall_address = syscall_address;
    event->got_address = got_address;
    event->relro_active = relro_active;
    event->got_offset = got_offset;

	bpf_ringbuf_submit(event, 0);
    return 0;
}
    



#endif