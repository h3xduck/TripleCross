#ifndef __MEM_CODE_CAVER_H
#define __MEM_CODE_CAVER_H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "../common/constants.h"

__u64 code_cave_find_address(__u64 min_cave_size, __u64 from, __u64 to, char flags[], __u32 pgoff, __u32 major, __u32 minor, __u64 ino){
    //printf("%x-%x %4c %x %x:%x %lu ");
    return 0;
}


#endif