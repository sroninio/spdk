#ifndef MYLIB_H
#define MYLIB_H

#define MAX_FH_DATA_LEN 300
#define MAX_FILE_NAME 300
#define REGULAR_STATE 1
#define PENDING_DELETION_STATE 2

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <stdbool.h>
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"
#include "libnfs-raw-nfs.h"
#include <spdk/barrier.h>

#ifdef __cplusplus
extern "C"
{
#endif

    struct persistent_nfs_fh3
    {
        struct
        {
            char data_val[MAX_FH_DATA_LEN];
            int data_len;
        } data;
    };

    struct NfsFsdevEntry
    {
        unsigned long inode_left_key;
        unsigned long ref_count;
        struct persistent_nfs_fh3 fh_right_key;
        int state;
        struct
        {
            struct persistent_nfs_fh3 parent_fh;
            char name[MAX_FILE_NAME];

        } reply_unlink_params;
    };

    void *allocate_and_init_map(char *filename);

    bool insert_entry(void *data_base, struct NfsFsdevEntry *entry, unsigned long left, struct persistent_nfs_fh3 *right);

    bool update_entry_by_left(void *data_base, struct NfsFsdevEntry *entry, unsigned long left);

    bool update_entry_by_right(void *data_base, struct NfsFsdevEntry *entry, struct persistent_nfs_fh3 *right);

    bool remove_entry_by_left(void *data_base, unsigned long left);

    bool remove_entry_by_right(void *data_base, struct persistent_nfs_fh3 *right);

    struct NfsFsdevEntry get_entry_by_left(void *data_base, unsigned long left);

    struct NfsFsdevEntry get_entry_by_right(void *data_base, struct persistent_nfs_fh3 *right);

    unsigned long generate_left_key(void *data_base);

    bool check_if_exist_by_left(void *data_base, unsigned long left);

    bool check_if_exist_by_right(void *data_base, struct persistent_nfs_fh3 *right);

#ifdef __cplusplus
}
#endif

#endif // MYLIB_H