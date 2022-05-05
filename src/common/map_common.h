#ifndef __MAP_COMMON_H
#define __MAP_COMMON_H

// Ring buffer for kernel->user communication
#define RB_EVENT_MAX_MESSAGE_SIZE 512
typedef enum {
    INFO,
    DEBUG,
    EXIT,
    ERROR,
    COMMAND
} event_type_t;

struct rb_event {
	int pid;
    char message[RB_EVENT_MAX_MESSAGE_SIZE];
    int code;
    event_type_t event_type;
};

#endif
