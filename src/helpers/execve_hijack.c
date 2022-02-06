#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char* argv[]){
    printf("Hello world from execve hijacker\n");
    for(int ii=0; ii<argc; ii++){
        printf("Argument %i is %s\n", ii, argv[ii]);
    }

    int fd = open("/tmp/testcreated", O_RDWR | O_CREAT | O_TRUNC, 0666);
    
    int ii = 0;
    while(*(argv[0]+ii)!='\0'){
        write(fd, argv[0]+ii, 1);
        ii++;
    }

    return 0;
}