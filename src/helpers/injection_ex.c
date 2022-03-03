#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>

int main(){
    struct link_map *lm;
	off_t offset = 0;
	unsigned long long dlopenAddr;
    lm = dlopen("libc.so.6", RTLD_LAZY);
	if(lm==0){
		perror("Error obtaining libc symbols");
		return -1;
	}
    dlopenAddr = (unsigned long long)dlsym((void*)lm, "__libc_dlopen_mode");
    printf("libdl: %lx\n", lm->l_addr);
	printf("dlopen: %llx\n", dlopenAddr);
	offset = dlopenAddr - lm->l_addr;
	printf("Offset: %lx\n", offset);

    return 0;
}