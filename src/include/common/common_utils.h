#ifndef __COMMON_UTILS_H__
#define __COMMON_UTILS_H__

/**
* Compares two strings.
* Yes, we cannot use strcmp from ebpf.
* https://github.com/iovisor/bcc/issues/691
*
* Misteriouslly we can from xdp_filter, but it might not work somewhere else.
* However it is the verifier which does not let us call strncmp without 
* additional checks so we will use this one anyway.
*
* @param str1
* @param str1len //Just to please the ebpf verifier
* @param str2
* @param str2len //Just to please the ebpf verifier
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

/**
 * Implementation of strncpy from the Linux Kernel. 
 * strncpy - Copy a length-limited, C-string
 * @dest: Where to copy the string to
 * @src: Where to copy the string from
 * @count: The maximum number of bytes to copy
 *
 * The result is not %NUL-terminated if the source exceeds
 * @count bytes.
 *
 * In the case where the length of @src is less than  that  of
 * count, the remainder of @dest will be padded with %NUL.
 *
 */
static __always_inline char* str_n_copy(char *dest, const char *src, int count){
	char *tmp = dest;

	while (count) {
		if ((*tmp = *src) != 0)
			src++;
		tmp++;
		count--;
	}
	return dest;
}




#endif