#ifndef __MEM_INJECTION_EXT_H
#define __MEM_INJECTION_EXT_H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../common/constants.h"
#include "../common/map_common.h"

int manage_injection(const struct rb_event* event){
    char mem_file_name[100];
    char *buf="AAAAAAAAAAAAA";
    int mem_fd;


    memset( (void*)mem_file_name, 0, 100);

    printf("Injecting at PID %d at %llx\n", event->pid, event->got_address);

    sprintf(mem_file_name, "/proc/%d/mem", event->pid);
    mem_fd = open(mem_file_name, O_RDWR);
    lseek(mem_fd, event->got_address, SEEK_SET);

    for(int ii=0; ii<8; ii++){
        if(write(mem_fd, buf, 1) < 0 ){
            perror("Writing");
        }
    }
    

    return 0;
}

#endif