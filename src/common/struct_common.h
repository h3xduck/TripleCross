#ifndef __H_STRUCT_COMMON
#define __H_STRUCT_COMMON


struct backdoor_phantom_shell_data{
	int active;
	unsigned int d_ip;
	unsigned short d_port;
	char payload[64];
};


#endif