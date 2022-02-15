#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

int main(int argc, char* argv[]){
    printf("Hello world from execve hijacker\n");

    time_t rawtime;
    struct tm * timeinfo;

    time ( &rawtime );
    timeinfo = localtime ( &rawtime );
    char* timestr = asctime(timeinfo);

    for(int ii=0; ii<argc; ii++){
        printf("Argument %i is %s\n", ii, argv[ii]);
    }

    //We proceed to fork() and exec the original program, whilst also executing the one we 
    //ordered to execute via the network backdoor
    //int bpf_map_fd = bpf_map_get_fd_by_id()

    int fd = open("/tmp/execve_hijack", O_RDWR | O_CREAT | O_TRUNC, 0666);
    
    int ii = 0;
    while(*(timestr+ii)!='\0'){
        write(fd, timestr+ii, 1);
        ii++;
    }
    write(fd, "\t", 1);
    
    ii = 0;
    while(*(argv[0]+ii)!='\0'){
        write(fd, argv[0]+ii, 1);
        ii++;
    }

    write(fd, "\n", 1);

    close(fd);

    return 0;
}