#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char* argv[], char *envp[]){
    printf("Hello world from the canalizer\n");
    char* args[] = {"sudo", "/home/osboxes/TFG/src/helpers/execve_hijack", NULL};
    execve("/usr/bin/sudo", args, envp);

    return 0;
}