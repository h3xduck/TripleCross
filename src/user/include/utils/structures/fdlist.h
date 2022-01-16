#ifndef __FDLIST_H
#define __FDLIST_H

typedef struct FdList{
    int size;
    int max_size;
    int* list;

} FdList;

FdList* FdList_create(int size);

int FdList_add(FdList *fd_list, int fd_new);

int FdList_extend(FdList *fd_list, int new_size);

int FdList_destroy(FdList *fd_list);


#endif