#ifndef __XDP_FILTER_H
#define __XDP_FILTER_H

#define MAX_PAYLOAD_LEN 127

struct event {
	char payload[MAX_PAYLOAD_LEN];
	//bool exit_event;
};

#endif
