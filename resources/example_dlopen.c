#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dlfcn.h>

int main(int argc, char* argv[]){
    
    void *handle = dlopen("/home/osboxes/TFG/src/helpers/injection_lib.so", RTLD_LAZY);
    
    if(handle==NULL){
        perror(dlerror());
    }

    return 0;
}