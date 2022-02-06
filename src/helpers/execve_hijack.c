#include <stdio.h>

int main(int argc, char* argv[]){
    printf("Hello world from execve hijacker\n");
    for(int ii=0; ii<argc; ii++){
        printf("Argument %i is %s\n", ii, argv[ii]);
    }
    return 0;
}