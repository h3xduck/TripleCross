#ifndef __RING_BUFFER_H
#define __RING_BUFFER_H

/*#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>*/
#include "newnewvmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../../../common/map_defs.h"

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
    



#endif