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
    void *create_my_map(void);
    struct nfs_fh3 *my_get(void *map, unsigned long key);
    void my_insert(void *map, unsigned long key, struct nfs_fh3 *fh);

#ifdef __cplusplus
}
#endif

#endif // MYLIB_H
