#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

__attribute__((constructor))
static void init()
{
    printf("Library successfully injected!\n");
    syslog(LOG_CRIT, "Library called\n");
}