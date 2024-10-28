#ifndef MYLIB_H
#define MYLIB_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <stdbool.h>
#include "volatile_map.h"
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"
#include "libnfs-raw-nfs.h"
#include <spdk/barrier.h>
#include <string_view>
#include "generic_persistent_map.h"
#include <new>

struct NfsFsdevEntry;

#ifdef __cplusplus
extern "C"
{
#endif

    void *allocate_and_init_map(char *filename);

    bool InsertEntry(void *data_base, struct NfsFsdevEntry *entry, unsigned long left, struct nfs_fh3 *right);

    bool UpdateEntryByLeft(void *data_base, struct NfsFsdevEntry *entry, unsigned long left);

    bool UpdateEntryByRight(void *data_base, struct NfsFsdevEntry *entry, struct nfs_fh3 *right);

    bool RemoveEntryByLeft(void *data_base, unsigned long left);

    bool RemoveEntryByRight(void *data_base, struct nfs_fh3 *right);

    struct NfsFsdevEntry GetEntryByLeft(void *data_base, unsigned long left);

    struct NfsFsdevEntry GetEntryByRight(void *data_base, struct nfs_fh3 *right);

#ifdef __cplusplus
}
#endif

#endif // MYLIB_H