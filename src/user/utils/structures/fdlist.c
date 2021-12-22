#include <stdlib.h>
#include <stdio.h>

#include "fdlist.h"


/**
 * @brief Creates a new fdlist with a given size
 * 
 * @param size 
 * @return FdList 
 */
FdList FdList_create(int size){
    FdList *fd_list = (FdList*)calloc(1, sizeof(FdList));
    fd_list->max_size = size;
    fd_list->size = 0;
    fd_list->list = (int*)calloc(size, sizeof(int));
}

/**
 * @brief Adds a new fd to the list 
 * 
 * @param fd_list 
 * @param fd_new 
 * @return 0 ok, -1 error
 */
int FdList_add(FdList *fd_list, int fd_new){
    if(fd_list->size+1 >= fd_list->max_size){
        return -1;
    }
}

/**
 * @brief Extends size of list
 * 
 * @param fd_list 
 * @param new_size 
 * @return int 
 */
int FdList_extend(FdList *fd_list, int new_size){
    fd_list->list = (int*)realloc(fd_list->list, new_size);
    return 0;
}

/**
 * @brief Destroy list
 * 
 * @param fd_list 
 * @return int 
 */
int FdList_destroy(FdList *fd_list){
    free(fd_list->list);
    free(fd_list);
}