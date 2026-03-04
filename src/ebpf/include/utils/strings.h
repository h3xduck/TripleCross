#ifndef __UTILS_STRINGS_H__
#define __UTILS_STRINGS_H__

/**
* Compares two strings.
* Yes, we cannot use strcmp from ebpf.
* https://github.com/iovisor/bcc/issues/691
*
* Misteriouslly it works sometimes due to compiler optimizations, but it might not work somewhere else.
* It is the verifier which does not let us call strncmp without 
* additional checks so we will use this one anyway.
*
* @param str1
* @param str1len //Just to please the ebpf verifier
* @param str2
* @param str2len //Just to please the ebpf verifier
* @param size Number of bytes to check
* @return 0 if equal, -1 if false
*/
static __always_inline int str_n_compare(char* str1, int str1len, char* str2, int str2len, int size){
    for(int ii = 0; ii < size; ii++){
        if(str1len<ii){
            return -1;
        }
        if(str2len<ii){
            return -1;
        }
        if (str1[ii] != str2[ii]){
            return -1;
        }
    }
    return 0;
}

static __always_inline int hide_str_n_compare(const char *s1, const char *s2, int n) {
    for (int i = 0; i < 16; i++) {
        // 手动检查边界
        if (i >= n) break;
        
        if (s1[i] != s2[i]) {
            return -1;
        }
        // 如果 s2 提前结束，说明匹配
        if (s2[i] == '\0') {
            return 0;
        }
    }
    return 0;
}




#endif