#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

__attribute__((constructor))
static void init()
{
    printf("It worked\n");
    syslog(LOG_CRIT, "Library called\n");
}