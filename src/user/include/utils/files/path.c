#define _XOPEN_SOURCE 700
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64 
#include <stdlib.h>
#include <unistd.h>
#include <ftw.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "path.h"
#include "../structures/fdlist.h"
#include "../strings/regex.h"
#define USE_FDS 15

//Global variable for the parameter fd_list, there is no other better way of doing this
FdList* fd_param;

int print_entry(const char *filepath, const struct stat *info, const int typeflag, struct FTW *pathinfo){
    /* const char *const filename = filepath + pathinfo->base; */

    //Symlinks
    if (typeflag == FTW_SL) {
        char   *target;
        size_t  maxlen = 1023;
        ssize_t len;
        while (1) {
            target = malloc(maxlen + 1);
            if (target == NULL)
                return ENOMEM;
            //Path too long, aborting
            len = readlink(filepath, target, maxlen);
            if (len == (ssize_t)-1) {
                const int saved_errno = errno;
                free(target);
                return saved_errno;
            }

            if (len >= (ssize_t)maxlen) {
                free(target);
                maxlen += 1024;
                continue;
            }
            target[len] = '\0';
            break;
        }

        //Checking if target corresponds to the 
        if(regex_match_fd(filepath)==0){
            
            //Add to fdlist
            printf(" %s -> %s\n", filepath, target);
        }
        free(target);

    }/*else
    if (typeflag == FTW_SLN)
        printf(" %s (dangling symlink)\n", filepath);*/
    else
    if (typeflag == FTW_F)
        printf(" %s\n", filepath);
    /*else
    if (typeflag == FTW_D || typeflag == FTW_DP)
        printf(" %s/\n", filepath);
    else
    if (typeflag == FTW_DNR)
        printf(" %s/ (unreadable)\n", filepath);
    else
        printf(" %s (unknown)\n", filepath);*/

    return 0;
}

/**
 * @brief 
 * 
 * @param dirpath 
 * @return NULL if error, FDList with elements matching kmsg fd if OK 
 */
FdList* load_fd_kmsg(const char *const dirpath){
    int res;
    fd_param = FdList_create(100);

    // Invalid directory path?
    if(dirpath == NULL || *dirpath == '\0'){
        return NULL;
    }

    //Physical walk, but we follow symlinks in the subroutine
    res = nftw(dirpath, print_entry, USE_FDS, FTW_PHYS);
    if (res >= 0){
        return NULL;
    }

    return fd_param;
}