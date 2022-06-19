/**
 * Modified version of Linux man page timer using timerfd.
 * Counts to 3, 1 second at a time, then sets another time up to 3, one second at a time.
 */

#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char *argv[]) {
    char* args[] = {"bash", "-c", "pwd", NULL}; 
    char* envp[] = {NULL}; 
    sleep(1);
    if(execve("/usr/bin/bash", args, envp)<0){
        perror("Failed to execve()");
        exit(-1);
    }
    return 0;
}