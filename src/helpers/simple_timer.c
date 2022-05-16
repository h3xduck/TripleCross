/**
 * Modified version of Linux man page timer using timerfd.
 * Counts to 3, 1 second at a time, then sets another time up to 3, one second at a time.
 */

#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

void print_elapsed_time() {
    static struct timespec start;
    struct timespec curr;
    static int first_call = 1;
    int secs, nsecs;

    if (first_call) {
        first_call = 0;
        if (clock_gettime(CLOCK_MONOTONIC, &start) == -1){
            perror("clock_gettime");
            return;   
        }
    }

    if (clock_gettime(CLOCK_MONOTONIC, &curr) == -1){
        perror("clock_gettime");
        return;
    }
        
    secs = curr.tv_sec - start.tv_sec;
    nsecs = curr.tv_nsec - start.tv_nsec;
    if (nsecs < 0) {
        secs--;
        nsecs += 1000000000;
    }
    printf("Timer called at: %d.%03d: ", secs, (nsecs + 500000) / 1000000);
}

int main(int argc, char *argv[]) {
    struct itimerspec new_value;
    int max_exp, fd;
    struct timespec now;
    uint64_t exp;
    ssize_t s;

    if (clock_gettime(CLOCK_REALTIME, &now) == -1){
        perror("clock_gettime");
        return -1;
    }
       
    new_value.it_value.tv_sec = now.tv_sec +1;
    new_value.it_value.tv_nsec = now.tv_nsec;
    new_value.it_interval.tv_sec = 1;
    new_value.it_interval.tv_nsec = 0;
    max_exp = 3;

    fd = timerfd_create(CLOCK_REALTIME, 0);
    if (fd == -1){
        perror("timerfd_create");
        return -1;
    }

    if (timerfd_settime(fd, TFD_TIMER_ABSTIME, &new_value, NULL) == -1){
        perror("timerfd_settime");
        return -1;
    }

    printf("Timer started\n");

    for (uint64_t tot_exp = 0; tot_exp < max_exp;) {
        s = read(fd, &exp, sizeof(uint64_t));
        if (s != sizeof(uint64_t))
            perror("Error reading from timer");

        tot_exp += exp;
        print_elapsed_time();
        printf("time between: %llu; total elapsed time=%llu\n", (unsigned long long) exp, (unsigned long long) tot_exp);
    }

    if (clock_gettime(CLOCK_REALTIME, &now) == -1){
        perror("clock_gettime");
        return -1;
    }

    new_value.it_value.tv_sec = now.tv_sec +1;
    new_value.it_value.tv_nsec = now.tv_nsec;
    new_value.it_interval.tv_sec = 1;
    new_value.it_interval.tv_nsec = 0;
    max_exp = 3;

    if (timerfd_settime(fd, TFD_TIMER_ABSTIME, &new_value, NULL) == -1){
        perror("timerfd_settime");
        return -1;
    }

    for (uint64_t tot_exp = 0; tot_exp < max_exp;) {
        s = read(fd, &exp, sizeof(uint64_t));
        if (s != sizeof(uint64_t))
            perror("Error reading from timer");

        tot_exp += exp;
        print_elapsed_time();
        printf("time between: %llu; total elapsed time=%llu\n", (unsigned long long) exp, (unsigned long long) tot_exp);
    }


   return 0;
}