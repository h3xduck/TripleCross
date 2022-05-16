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
    int fd;
    char* path = "/home/osboxes/TFG/src/helpers/Makefile";
    openat(fd, path, O_RDONLY);
    //Second call
    openat(fd, path, O_RDONLY);

   return 0;
}