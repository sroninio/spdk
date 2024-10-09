#ifndef MYLIB_H
#define MYLIB_H

// #include "libnfs.h"
// #include "libnfs-raw.h"
// #include "libnfs-raw-mount.h"
// #include "libnfs-raw-nfs.h"
struct dataP //
{
    int data_len;
    char *data_val;
};
typedef struct dataP dataP; //

struct nfs_fh3 //
{
    dataP data;
};

#ifdef __cplusplus
extern "C"
{
#endif

    void *create_my_map(void);
    struct nfs_fh3 *my_get_value(void *map, unsigned long key, int *index);
    void my_insert(void *map, unsigned long key, struct nfs_fh3 *fh, int index);
    bool my_remove(void *map, unsigned long key);

#ifdef __cplusplus
}
#endif

#endif // MYLIB_H