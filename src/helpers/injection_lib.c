#include <stdio.h>

__attribute__((constructor))
static void init()
{
    puts("It worked\n");
}