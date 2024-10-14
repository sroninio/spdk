#ifndef MYLIB_H
#define MYLIB_H

#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"
#include "libnfs-raw-nfs.h"

#ifdef __cplusplus
extern "C"
{
#endif

    void *create_volatile_map(void);
    struct nfs_fh3 *volatile_map_get_value(void *map, unsigned long key, int *index);
    void volatile_map_insert(void *map, unsigned long key, struct nfs_fh3 *fh, int index);
    bool volatile_map_remove(void *map, unsigned long key);
    bool volatile_map_is_fh_exist(void *map, struct nfs_fh3 *fh, unsigned long *answer);

#ifdef __cplusplus
}
#endif

#endif // MYLIB_H