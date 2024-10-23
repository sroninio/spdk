/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */
#include "spdk/stdinc.h"
#include "spdk/event.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "spdk/config.h"
#include "spdk/util.h"
#include "spdk/thread.h"
#include "fsdev_nfs.h"
#include <sys/sysmacros.h> // For makedev
#include <sys/stat.h>      // For S_ISCHR and S_ISBLK
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <fcntl.h>
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"
#include "libnfs-raw-nfs.h"

#include "persistent_map.h"

#define ST_ATIM_NSEC(stbuf) ((stbuf)->st_atim.tv_nsec)
#define ST_CTIM_NSEC(stbuf) ((stbuf)->st_ctim.tv_nsec)
#define ST_MTIM_NSEC(stbuf) ((stbuf)->st_mtim.tv_nsec)
#define ST_ATIM_NSEC_SET(stbuf, val) (stbuf)->st_atim.tv_nsec = (val)
#define ST_CTIM_NSEC_SET(stbuf, val) (stbuf)->st_ctim.tv_nsec = (val)
#define ST_MTIM_NSEC_SET(stbuf, val) (stbuf)->st_mtim.tv_nsec = (val)
#define INVALIDINODE 16

#define MAX_BACKGROUND (100)
#define TIME_GRAN (1)
#define MAX_AIOS 256
#define DEFAULT_WRITEBACK_CACHE true
#define DEFAULT_MAX_XFER_SIZE 0x00020000
#define DEFAULT_MAX_READAHEAD 0x00020000
#define DEFAULT_XATTR_ENABLED false
#define DEFAULT_SKIP_RW false
#define DEFAULT_TIMEOUT_MS 0 /* to prevent the attribute caching */
#define INVALID_INODE 0
#define XID_OFFSET 400000

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WIN32
#include <win32/win32_compat.h>
#pragma comment(lib, "ws2_32.lib")
WSADATA wsaData;
#else
#include <sys/stat.h>
#endif

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#define OP_STATUS_ASYNC INT_MIN

const struct nfs_fh *
nfs_get_rootfh(struct nfs_context *nfs);

struct nfs_fsdev
{
    struct spdk_fsdev fsdev;
    char *server;
    char *export;
    DB *db;
};

struct nfs_io_channel
{
    struct spdk_poller *poller;
    struct nfs_context *nfs;
    struct pollfd pfds[2]; /* nfs:0  mount:1 */
};

struct nfs_fsdev_io_device
{
    struct nfs_fsdev *nfs_fsdev;
    struct nfs_io_channel *nfs_io_channel;
};

struct lo_cred
{
    uid_t euid;
    gid_t egid;
};

/** Inode number type */
typedef uint64_t spdk_ino_t;

struct lo_key
{
    ino_t ino;
    dev_t dev;
};

struct fsdev_and_fsdev_io
{
    struct nfs_fsdev *vfsdev;
    struct spdk_fsdev_io *fsdev_io;
    struct spdk_io_channel *_ch;
    unsigned long key;
};
typedef struct fsdev_and_fsdev_io fsdev_and_fsdev_io;

static inline struct nfs_fsdev_io_device *
fsdev_to_nfs_io(const struct spdk_fsdev_io *fsdev_io)
{
    return (struct nfs_fsdev_io_device *)fsdev_io->driver_ctx;
}

static inline struct spdk_fsdev_io *
nfs_to_fsdev_io(const struct nfs_fsdev_io_device *nfs_io)
{
    return SPDK_CONTAINEROF(nfs_io, struct spdk_fsdev_io, driver_ctx);
}

static inline struct nfs_fsdev *
fsdev_to_nfs_fsdev(struct spdk_fsdev *fsdev)
{
    return SPDK_CONTAINEROF(fsdev, struct nfs_fsdev, fsdev);
}

static void
lo_fill_attr(struct spdk_fsdev_file_attr *dest, fattr3 *res, int inode)
{
    dest->ino = inode;
    dest->size = res->size;
    dest->blocks = (res->size + 511) / 512;
    dest->atime = res->atime.seconds;
    dest->mtime = res->mtime.seconds;
    dest->ctime = res->ctime.seconds;
    dest->atimensec = res->atime.nseconds;
    dest->mtimensec = res->mtime.nseconds;
    dest->ctimensec = res->ctime.nseconds;

    switch (res->type)
    {
    case NF3REG:
        dest->mode = 0100000 + res->mode; // Regular file
        break;
    case NF3DIR:
        dest->mode = 0040000 + res->mode; // Directory
        break;
    case NF3BLK:
        dest->mode = 0060000 + res->mode; // Block special
        break;
    case NF3CHR:
        dest->mode = 0020000 + res->mode; // Character special
        break;
    case NF3LNK:
        dest->mode = 0120000 + res->mode; // Symbolic link
        break;
    case NF3SOCK:
        dest->mode = 0140000 + res->mode; // Socket
        break;
    case NF3FIFO:
        dest->mode = 0010000 + res->mode; // FIFO
        break;
    default:
        // Handle unexpected file type as Regular file
        dest->mode = 0100000 + res->mode;
        SPDK_ERRLOG("Unexpected file type: %d\n", res->type); // this is not neccerliy an error (!?)
        break;
    }

    dest->nlink = res->nlink;
    dest->uid = res->uid;
    dest->gid = res->gid;

    if (S_ISCHR(res->mode) || S_ISBLK(res->mode))
    {
        dest->rdev = makedev(res->rdev.specdata1, res->rdev.specdata2);
    }
    else
    {
        dest->rdev = 0;
    }

    dest->blksize = 4096;
    dest->valid_ms = 0;
}

static int
lo_open(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
    printf("+=+=+=+=+=+=+=+=  {lo_open} FUNCTION CALLED \n");
    fsdev_io->u_out.open.fhandle = (struct spdk_fsdev_file_handle *)fsdev_io->u_in.open.fobject;
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);

    if (is_valid_entry_db(vfsdev->db, (unsigned long)fsdev_io->u_in.open.fobject) == false)
    {
        printf("Error: trying to OPEN an file that is pending deletion\n");
        return -EINVAL;
    }

    increment_ref_count_db(vfsdev->db, (unsigned long)fsdev_io->u_in.open.fobject);
    return 0;
}

static void
lo_write_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    printf("+=+=+=+=+=+=+=+=  {lo_write_cb} FUNCTION CALLED \n");

    struct spdk_fsdev_io *fsdev_io = private_data;
    if (status == RPC_STATUS_ERROR)
    {
        printf("read failed with error [%s]\n", (char *)data);
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("read failed \n");
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    fsdev_io->u_out.write.data_size = fsdev_io->u_in.write.size;

    spdk_fsdev_io_complete(fsdev_io, 0);
}

static int
lo_write(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    printf("+=+=+=+=+=+=+=+=  {lo_write} FUNCTION CALLED \n");
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);

    if (fsdev_io->u_in.write.fhandle != (struct spdk_fsdev_file_handle *)fsdev_io->u_in.write.fobject)
    {
        printf("fh != fobj when should be equal\n");
        return -EINVAL;
    }

    unsigned long inode_key = (unsigned long)fsdev_io->u_in.read.fhandle;

    struct nfs_fh3 *fh = get_db(vfsdev->db, inode_key);

    size_t size = fsdev_io->u_in.write.size;
    uint64_t offs = fsdev_io->u_in.write.offs;
    const struct iovec *invec = fsdev_io->u_in.write.iov;

    struct WRITE3args args = {0};
    args.file = *fh;
    args.offset = offs;
    args.count = size;
    args.data.data_val = invec[0].iov_base;
    args.data.data_len = size;

    args.stable = FILE_SYNC;
    /* The choice of stability affects the trade-off between performance and data safety:
       UNSTABLE is fastest but least safe
       FILE_SYNC is slowest but most safe
       DATA_SYNC is a middle ground
    */

    if (rpc_nfs3_write_task(nfs_get_rpc_context(vch->nfs),
                            lo_write_cb, &args, fsdev_io) == NULL)
    {
        printf("error in write opertion\n");
        return -EINVAL;
    }

    return OP_STATUS_ASYNC;
}

static void
lo_read_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    printf("+=+=+=+=+=+=+=+=  {lo_read_cb} FUNCTION CALLED \n");

    struct spdk_fsdev_io *fsdev_io = private_data;
    if (status == RPC_STATUS_ERROR)
    {
        printf("read failed with error [%s]\n", (char *)data);
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("read failed \n");
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    struct READ3res *result = data;

    printf("reached here 1 \n");
    printf("reached here 2 \n");

    fsdev_io->u_out.read.data_size = result->READ3res_u.resok.count;

    spdk_fsdev_io_complete(fsdev_io, 0);
}

static int
lo_read(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    printf("+=+=+=+=+=+=+=+=  {lo_read} FUNCTION CALLED \n");

    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);

    if (fsdev_io->u_in.read.fhandle != (struct spdk_fsdev_file_handle *)fsdev_io->u_in.read.fobject)
    {
        printf("fh != fobj when should be equal\n");
        return -EINVAL;
    }

    unsigned long inode_key = (unsigned long)fsdev_io->u_in.read.fhandle;

    struct nfs_fh3 *fh = get_db(vfsdev->db, inode_key);

    struct iovec *outvec = fsdev_io->u_in.read.iov;
    uint64_t offset = fsdev_io->u_in.read.offs;

    struct READ3args args = {0};
    args.file = *fh;
    args.offset = offset;
    args.count = outvec[0].iov_len;

    if (rpc_nfs3_read_task(nfs_get_rpc_context(vch->nfs), lo_read_cb, outvec[0].iov_base,
                           outvec[0].iov_len, &args, fsdev_io) == NULL)
    {
        printf("error in read request \n");
        return -EINVAL;
    }
    return OP_STATUS_ASYNC;
}

static void
lo_getattr_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    printf("+=+=+=+=+=+=+=+=  {lo_getattr_cb} FUNCTION CALLED \n");
    fflush(stdout);

    struct spdk_fsdev_io *fsdev_io = private_data;

    if (status == RPC_STATUS_ERROR)
    {
        printf("getattr failed with error [%s]\n", (char *)data);
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("getattr failed \n");
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }

    struct GETATTR3res *result = data;
    fattr3 *res = &result->GETATTR3res_u.resok.obj_attributes;
    lo_fill_attr(&fsdev_io->u_out.getattr.attr, res, (unsigned long)fsdev_io->u_in.getattr.fobject);

    spdk_fsdev_io_complete(fsdev_io, 0);
}

static int
lo_getattr(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    unsigned long key = (unsigned long)fsdev_io->u_in.getattr.fobject;
    printf("+=+=+=+=+=+=+=+=  {lo_getattr} FUNCTION CALLED with inode number [%ld] \n", key);

    struct GETATTR3args args = {0};

    struct nfs_fh3 *nfsfh = get_db(vfsdev->db, key);

    if (nfsfh == NULL)
    {
        printf("the file handle is NULL !! \n");
        return -EINVAL;
    }

    if (nfsfh->data.data_val == 0)
    {
        printf("not in the map \n");
        return -EINVAL;
    }

    args.object = *nfsfh;

    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);

    if (rpc_nfs3_getattr_task(nfs_get_rpc_context(vch->nfs), lo_getattr_cb, &args, fsdev_io) == NULL)
    {
        printf("error in getting attributes \n");
        return -EINVAL;
    }

    return OP_STATUS_ASYNC;
}

static int
lo_mount(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    fsdev_io->u_out.mount.root_fobject = (struct spdk_fsdev_file_object *)1;

    fsdev_io->u_out.mount.opts = fsdev_io->u_in.mount.opts;

    fsdev_io->u_out.mount.opts.max_readahead = DEFAULT_MAX_READAHEAD;

    fsdev_io->u_out.mount.opts.max_xfer_size = DEFAULT_MAX_XFER_SIZE;

    bool writeback_cache_enabled = false;

    uint64_t flags = 0;

#define AIO_SET_MOUNT_FLAG(cond, store, flag)                                     \
    if ((cond) && (fsdev_io->u_out.mount.opts.flags & (SPDK_FSDEV_MOUNT_##flag))) \
    {                                                                             \
        store |= (SPDK_FSDEV_MOUNT_##flag);                                       \
    }

    AIO_SET_MOUNT_FLAG(true, flags, DOT_PATH_LOOKUP);
    AIO_SET_MOUNT_FLAG(true, flags, AUTO_INVAL_DATA);
    AIO_SET_MOUNT_FLAG(true, flags, EXPLICIT_INVAL_DATA);
    AIO_SET_MOUNT_FLAG(true, flags, POSIX_ACL);

    /* Based on the setting above. */
    AIO_SET_MOUNT_FLAG(writeback_cache_enabled, flags, WRITEBACK_CACHE);

    /* Updating negotiated flags. */
    fsdev_io->u_out.mount.opts.flags = flags;

#undef AIO_SET_MOUNT_FLAG

    return 0;
}

static int
lo_umount(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    return 0;
}

static bool
lo_validate_and_insert_inode(unsigned long *new_key, struct nfs_fsdev *vfsdev, struct nfs_fh3 *fh)
{
    if (fh_exist_db(vfsdev->db, fh, new_key))
    {
        if (is_valid_entry_db(vfsdev->db, *new_key) == false)
        {
            return false;
        }

        increment_ref_count_db(vfsdev->db, *new_key);
    }
    else
    {
        *new_key = generate_new_key_db(vfsdev->db);
        insert_db(vfsdev->db, *new_key, fh);
    }
    return true;
}

static void
lo_lookup_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    printf("+=+=+=+=+=+=+=+=  {lo_lookup_cb} FUNCTION CALLED \n");

    struct spdk_fsdev_io *fsdev_io = private_data;
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);

    if (status == RPC_STATUS_ERROR)
    {
        printf("LOOKUP failed with error [%s]\n", (char *)data);
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("LOOKUP failed \n");
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    struct LOOKUP3res *result = data;
    struct nfs_fh3 *fh = &(result->LOOKUP3res_u.resok.object);
    nfsstat3 ret = result->status;
    if (ret != NFS3_OK)
    {
        if (ret == NFS3ERR_NOENT)
        {
            printf("reached here !!RET == NFS3ERR_NOENT \n");
            spdk_fsdev_io_complete(fsdev_io, -ENOENT);
        }
        else
        {
            printf("ERROR: lookup result is other than OK or NOENT = [%d]\n", ret);
            spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        }
        return;
    }

    unsigned long new_key = INVALID_INODE;
    if (lo_validate_and_insert_inode(&new_key, vfsdev, fh) == false)
    {
        printf("Error: trying to approach an entry that is pending deletion\n");
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }

    printf("$$$$$$ WE ARE RETURNNING INDOE %ld\n", new_key); //

    fsdev_io->u_out.lookup.fobject = (struct spdk_fsdev_file_object *)new_key;
    fattr3 *res = &result->LOOKUP3res_u.resok.obj_attributes.post_op_attr_u.attributes;
    lo_fill_attr(&fsdev_io->u_out.lookup.attr, res, new_key);

    spdk_fsdev_io_complete(fsdev_io, 0);
}

static int
lo_lookup(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    unsigned long key_parent = (unsigned long)fsdev_io->u_in.lookup.parent_fobject;
    char *name = fsdev_io->u_in.lookup.name;

    printf("+=+=+=+=+=+=+=+=  {lo_lookup} FUNCTION CALLED fuse_inode = %ld, name=%s\n", key_parent, name);
    fflush(stdout);

    if (key_parent == 0)
    {
        printf("\033[1;31mERROR ! WE ARE CALLING LOOK UP WITH PARENT INODE = 0 !!\033[0m\n");
        return -EINVAL;
    }

    struct nfs_fh3 *nfsfh_parent = get_db(vfsdev->db, key_parent);

    struct LOOKUP3args args = {0};

    args.what.dir = *nfsfh_parent;
    args.what.name = name;

    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);

    if (rpc_nfs3_lookup_task(nfs_get_rpc_context(vch->nfs), lo_lookup_cb, &args, fsdev_io) == NULL)
    {
        printf("ERROR in calling lookup\n");
        return -EINVAL;
    }

    return OP_STATUS_ASYNC;
}

static int
lo_opendir(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    printf("+=+=+=+=+=+=+=+=  {lo_opendir} FUNCTION CALLED \n");

    fsdev_io->u_out.open.fhandle = (struct spdk_fsdev_file_handle *)fsdev_io->u_in.open.fobject;
    return 0;
}

static void
lo_readdir_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    printf("+=+=+=+=+=+=+=+=  {lo_readdir_cb} FUNCTION CALLED \n");

    struct spdk_fsdev_io *fsdev_io = private_data;
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    if (status == RPC_STATUS_ERROR)
    {
        printf("READDIR failed with error [%s]\n", (char *)data);
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("READDIR failed \n");
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }

    struct READDIRPLUS3res *res = data;
    dirlistplus3 list_head = res->READDIRPLUS3res_u.resok.reply;
    entryplus3 *curr_entry = list_head.entries;
    while (curr_entry != NULL)
    {
        unsigned long new_key = INVALID_INODE;
        if (lo_validate_and_insert_inode(&new_key, vfsdev, &(curr_entry->name_handle.post_op_fh3_u.handle)) == false)
        {
            printf("Error: trying to approach an entry that is pending deletion so we are skipping inserting it to the map...\n");
            printf("we don't care that this entry is pending deletion.\n"); // maybe we should skip showing this entry ?!
            // spdk_fsdev_io_complete(fsdev_io, -EINVAL);
            // return;
        }

        //
        printf("READDIR ENTRY : NAME=[%s] AND GIVEN INODE [%ld]\n", curr_entry->name, new_key);
        printf("ENTRY DATA:   DATA_LEN =[%d], DATA_VAL =[",
               curr_entry->name_handle.post_op_fh3_u.handle.data.data_len);
        for (unsigned long j = 0; j < curr_entry->name_handle.post_op_fh3_u.handle.data.data_len; j++)
        {
            printf("%c", curr_entry->name_handle.post_op_fh3_u.handle.data.data_val[j]);
        }
        printf("]\n");
        //

        bool forget = false;
        fsdev_io->u_out.readdir.name = curr_entry->name;
        fsdev_io->u_out.readdir.offset = curr_entry->cookie;
        lo_fill_attr(&fsdev_io->u_out.readdir.attr, &curr_entry->name_attributes.post_op_attr_u.attributes, new_key);
        fsdev_io->u_out.readdir.fobject = (struct spdk_fsdev_file_object *)new_key;
        fsdev_io->u_in.readdir.entry_cb_fn(fsdev_io, fsdev_io->internal.cb_arg, &forget);
        curr_entry = curr_entry->nextentry;
    }

    spdk_fsdev_io_complete(fsdev_io, 0);
}

static int
lo_readdir(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{

    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);

    if (fsdev_io->u_in.readdir.fhandle != (struct spdk_fsdev_file_handle *)fsdev_io->u_in.readdir.fobject)
    {
        printf("Failed in readdir because fh != fobj when should be equal\n");
        return -EINVAL;
    }

    unsigned long key = (unsigned long)fsdev_io->u_in.readdir.fobject;

    struct nfs_fh3 *nfsfh = get_db(vfsdev->db, key);

    printf("+=+=+=+=+=+=+=+=  {lo_readdir} FUNCTION CALLED for inode number [%ld]\n", key);

    struct READDIRPLUS3args args = {0};
    args.dir = *nfsfh;
    args.cookie = fsdev_io->u_in.readdir.offset;
    args.dircount = 1000000;
    args.maxcount = 1000000;

    if (rpc_nfs3_readdirplus_task(nfs_get_rpc_context(vch->nfs), lo_readdir_cb, &args, fsdev_io) == NULL)
    {
        printf("ERROR in calling readdir\n");
        return -EINVAL;
    }

    return OP_STATUS_ASYNC;
}

static void
lo_create_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    printf("+=+=+=+=+=+=+=+=  {lo_create_cb} FUNCTION CALLED \n");

    struct spdk_fsdev_io *fsdev_io = private_data;
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    if (status == RPC_STATUS_ERROR)
    {
        printf("lo_create failed with error [%s]\n", (char *)data);
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("lo_create failed \n");
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    struct CREATE3res *result = data;
    if (result->status != NFS3_OK)
    {
        printf("ERROR: create returned error [%d]\n", result->status);
        spdk_fsdev_io_complete(fsdev_io, result->status);
        return;
    }

    unsigned long new_key = INVALID_INODE;
    if (lo_validate_and_insert_inode(&new_key, vfsdev, &result->CREATE3res_u.resok.obj.post_op_fh3_u.handle) == false)
    {
        printf("Error: trying to CREATE an entry that is pending deletion\n"); // but is this an error ??
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }

    fattr3 *res = &result->CREATE3res_u.resok.obj_attributes.post_op_attr_u.attributes;
    lo_fill_attr(&fsdev_io->u_out.mknod.attr, res, new_key);
    fsdev_io->u_out.mknod.fobject = (struct spdk_fsdev_file_object *)new_key;

    spdk_fsdev_io_complete(fsdev_io, 0);
}

static int
lo_mknod(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    printf("+=+=+=+=+=+=+=+=  {lo_mknod} FUNCTION CALLED \n");

    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);

    // Determine the file type (we can also extract it from rdev via major+minor )
    switch (fsdev_io->u_in.mknod.mode & 0170000) // 0170000 is the mask for file type bits
    {
    case 0100000: // regular files
        struct CREATE3args args2 = {0};

        args2.where.dir = *get_db(vfsdev->db, (unsigned long)fsdev_io->u_in.mknod.parent_fobject);

        args2.where.name = fsdev_io->u_in.mknod.name;

        // Or GUARDED, or EXCLUSIVE (UNCHECKED mode creates the file regardless of whether it exists. GUARDED fails if the file exists. EXCLUSIVE is for atomic file creation.)
        args2.how.mode = UNCHECKED;

        args2.how.createhow3_u.obj_attributes.mode.set_it = 1;
        args2.how.createhow3_u.obj_attributes.mode.set_mode3_u.mode = fsdev_io->u_in.mknod.mode & 0777;
        args2.how.createhow3_u.obj_attributes.uid.set_it = 1;
        args2.how.createhow3_u.obj_attributes.uid.set_uid3_u.uid = fsdev_io->u_in.mknod.euid;
        args2.how.createhow3_u.obj_attributes.gid.set_it = 1;
        args2.how.createhow3_u.obj_attributes.gid.set_gid3_u.gid = fsdev_io->u_in.mknod.egid;

        if (rpc_nfs3_create_task(nfs_get_rpc_context(vch->nfs), lo_create_cb, &args2, fsdev_io) == NULL)
        {
            printf("ERROR in calling create\n");
            return -EINVAL;
        }
        return OP_STATUS_ASYNC;
        break;
    default:
        printf("Unexpected file type in mode: %o\n", fsdev_io->u_in.mknod.mode);
        return -EINVAL;
    }
}

static void
lo_mkdir_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    printf("+=+=+=+=+=+=+=+=  {lo_mkdir_cb} FUNCTION CALLED \n");

    struct spdk_fsdev_io *fsdev_io = private_data;
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    if (status == RPC_STATUS_ERROR)
    {
        printf("lo_mkdir failed with error [%s]\n", (char *)data);
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("lo_mkdir failed \n");
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }

    struct MKDIR3res *result = data;
    if(result->){
        
    }



    unsigned long new_key = INVALID_INODE;
    if (lo_validate_and_insert_inode(&new_key, vfsdev, &result->MKDIR3res_u.resok.obj.post_op_fh3_u.handle) == false)
    {
        printf("Error: trying to MKDIR an entry that is pending deletion\n"); // but is this an error ??
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }

    fattr3 *res = &result->MKDIR3res_u.resok.obj_attributes.post_op_attr_u.attributes;
    lo_fill_attr(&fsdev_io->u_out.mkdir.attr, res, new_key);
    fsdev_io->u_out.mkdir.fobject = (struct spdk_fsdev_file_object *)new_key;

    spdk_fsdev_io_complete(fsdev_io, 0);
}

static int
lo_mkdir(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    printf("+=+=+=+=+=+=+=+=  {lo_mkdir} FUNCTION CALLED \n");

    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);

    struct MKDIR3args args = {0};
    args.where.dir = *get_db(vfsdev->db, (unsigned long)fsdev_io->u_in.mkdir.parent_fobject);
    args.where.name = fsdev_io->u_in.mkdir.name;
    args.attributes.gid.set_it = 1;
    args.attributes.gid.set_gid3_u.gid = fsdev_io->u_in.mkdir.egid;
    args.attributes.uid.set_it = 1;
    args.attributes.uid.set_uid3_u.uid = fsdev_io->u_in.mkdir.euid;
    args.attributes.mode.set_it = 1;
    args.attributes.mode.set_mode3_u.mode = fsdev_io->u_in.mkdir.mode & 0777;

    if (rpc_nfs3_mkdir_task(nfs_get_rpc_context(vch->nfs), lo_mkdir_cb, &args, fsdev_io) == NULL)
    {
        printf("ERROR in calling mkdir\n");
        return -EINVAL;
    }
    return OP_STATUS_ASYNC;
}

static void
lo_setattr_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    printf("+=+=+=+=+=+=+=+=  {lo_setattr_cb} FUNCTION CALLED \n");
    fflush(stdout);

    struct spdk_fsdev_io *fsdev_io = private_data;

    if (status == RPC_STATUS_ERROR)
    {
        printf("setattr failed with error [%s]\n", (char *)data);
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("setattr failed \n");
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    struct SETATTR3res *result = data;
    fattr3 *res = &result->SETATTR3res_u.resok.obj_wcc.after.post_op_attr_u.attributes;
    lo_fill_attr(&fsdev_io->u_out.setattr.attr, res, (unsigned long)fsdev_io->u_in.setattr.fobject);

    spdk_fsdev_io_complete(fsdev_io, 0);
}

static int
lo_setattr(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    unsigned long key = (unsigned long)fsdev_io->u_in.setattr.fobject;
    printf("+=+=+=+=+=+=+=+=  {lo_setattr} FUNCTION CALLED with inode number [%ld] \n", key);
    struct spdk_fsdev_file_attr *attr = &fsdev_io->u_in.setattr.attr;

    struct nfs_fh3 *nfsfh = get_db(vfsdev->db, key);

    struct SETATTR3args args = {0};

    args.object = *nfsfh;

    if (fsdev_io->u_in.setattr.to_set & (FSDEV_SET_ATTR_ATIME | FSDEV_SET_ATTR_MTIME))
    {
        args.new_attributes.atime.set_it = 1;
        args.new_attributes.atime.set_atime_u.atime.seconds = attr->atime;
        args.new_attributes.atime.set_atime_u.atime.nseconds = attr->atimensec;

        args.new_attributes.mtime.set_it = 1;
        args.new_attributes.mtime.set_mtime_u.mtime.seconds = attr->mtime;
        args.new_attributes.mtime.set_mtime_u.mtime.nseconds = attr->mtimensec;
    }

    if (fsdev_io->u_in.setattr.to_set & (FSDEV_SET_ATTR_UID | FSDEV_SET_ATTR_GID))
    {
        args.new_attributes.gid.set_it = 1;
        args.new_attributes.gid.set_gid3_u.gid = attr->gid;

        args.new_attributes.uid.set_it = 1;
        args.new_attributes.uid.set_uid3_u.uid = attr->uid;
    }

    if (fsdev_io->u_in.setattr.to_set & FSDEV_SET_ATTR_SIZE)
    {
        args.new_attributes.size.set_it = 1;
        args.new_attributes.size.set_size3_u.size = attr->size;
    }

    if (fsdev_io->u_in.setattr.to_set & FSDEV_SET_ATTR_MODE)
    {
        args.new_attributes.mode.set_it = 1;
        args.new_attributes.mode.set_mode3_u.mode = attr->mode & 0777;
    }
    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);

    if (rpc_nfs3_setattr_task(nfs_get_rpc_context(vch->nfs), lo_setattr_cb, &args, fsdev_io) == NULL)
    {
        printf("error in setting attributes \n");
        return -EINVAL;
    }

    return OP_STATUS_ASYNC;
}

static fsdev_and_fsdev_io *
lo_allocate_and_initialize_cb_data(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    fsdev_and_fsdev_io *cb_data = calloc(1, sizeof(*cb_data));
    cb_data->vfsdev = vfsdev;
    cb_data->fsdev_io = fsdev_io;
    cb_data->_ch = _ch;
    cb_data->key = INVALID_INODE;
    return cb_data;
}

static void
lo_unlink_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    printf("+=+=+=+=+=+=+=+=  {lo_unlink_cb} FUNCTION CALLED \n");
    fflush(stdout);

    fsdev_and_fsdev_io *cb_data = private_data;
    struct spdk_fsdev_io *fsdev_io = cb_data->fsdev_io;

    if (status == RPC_STATUS_ERROR)
    {
        printf("unlink failed with error [%s]\n", (char *)data);
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("unlink failed \n");
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }

    delete_entry_db(cb_data->vfsdev->db, cb_data->key);

    free(cb_data);
    spdk_fsdev_io_complete(fsdev_io, 0);
}

static void
lo_unlink_lookup_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    printf("+=+=+=+=+=+=+=+=  {lo_unlink_lookup_cb} FUNCTION CALLED \n");
    fflush(stdout);

    fsdev_and_fsdev_io *cb_data = private_data;
    struct spdk_io_channel *_ch = cb_data->_ch;
    struct spdk_fsdev_io *fsdev_io = cb_data->fsdev_io;
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);

    if (status == RPC_STATUS_ERROR)
    {
        printf("LOOKUP FROM UNLINK failed with error [%s]\n", (char *)data);
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("LOOKUP FROM UNLINK failed \n");
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }

    struct LOOKUP3res *result = data;
    struct nfs_fh3 *fh = &(result->LOOKUP3res_u.resok.object);
    nfsstat3 ret = result->status;

    if (ret != NFS3_OK)
    {
        if (ret == NFS3ERR_NOENT)
        {
            printf("reached here !!RET == NFS3ERR_NOENT \n");
            spdk_fsdev_io_complete(fsdev_io, -ENOENT);
            printf("yy\n");
        }
        else
        {
            printf("ERROR: lookup result is other than OK or NOENT = [%d]\n", ret);
            spdk_fsdev_io_complete(fsdev_io, -EINVAL);
            printf("xx\n");
        }
        return;
    }

    unsigned long new_key = INVALID_INODE;
    if (fh_exist_db(vfsdev->db, fh, &new_key))
    {
        if (get_ref_count_db(vfsdev->db, new_key) == 0)
        {
            if (is_valid_entry_db(vfsdev->db, new_key) == false)
            {
                printf("Trying to UNLINK a file that is already pending deletion\n"); // recovery problem
                // spdk_fsdev_io_complete(fsdev_io, -EINVAL);
                // return;
            }
            set_pending_deletion_flag(vfsdev->db, new_key);
        }
        else
        {
            printf("ERROR: Trying to UNLINK a file that has positive refrence count \n");
            spdk_fsdev_io_complete(fsdev_io, -EINVAL);
            return;
        }
    }
    else
    {
        new_key = generate_new_key_db(vfsdev->db);
        insert_db(vfsdev->db, new_key, fh);
        set_pending_deletion_flag(vfsdev->db, new_key);
    }
    cb_data->key = new_key;

    struct REMOVE3args args = {0};
    args.object.dir = *get_db(vfsdev->db, (unsigned long)fsdev_io->u_in.unlink.parent_fobject);
    args.object.name = fsdev_io->u_in.unlink.name;
    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);

    rpc_set_next_xid(nfs_get_rpc_context(vch->nfs), (unsigned int)(fsdev_io->internal.unique));

    if (rpc_nfs3_remove_task(nfs_get_rpc_context(vch->nfs), lo_unlink_cb, &args, cb_data) == NULL)
    {
        printf("ERROR: in unlinking a file \n");
            spdk_fsdev_io_complete(fsdev_io, -EINVAL);
            return;
    }
}

static int
lo_unlink(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    unsigned long key_parent = (unsigned long)fsdev_io->u_in.unlink.parent_fobject;
    char *name = fsdev_io->u_in.unlink.name;

    if (key_parent == 0)
    {
        printf("\033[1;31mERROR ! WE ARE CALLING LOOK UP WITH PARENT INODE = 0 !! \n Trying to delete root directory \033[0m\n");
        return -EINVAL;
    }

    struct nfs_fh3 *nfsfh_parent = get_db(vfsdev->db, key_parent);

    struct LOOKUP3args args = {0};
    args.what.dir = *nfsfh_parent;
    args.what.name = name;

    fsdev_and_fsdev_io *cb_data = lo_allocate_and_initialize_cb_data(_ch, fsdev_io);

    if (fsdev_io->internal.unique + XID_OFFSET > 0xffffffff)
    {
        printf("Error: xid out of bounds\n");
        return -EINVAL;
    }

    rpc_set_next_xid(nfs_get_rpc_context(vch->nfs), (unsigned int)(fsdev_io->internal.unique + (unsigned long)XID_OFFSET));

    if (rpc_nfs3_lookup_task(nfs_get_rpc_context(vch->nfs), lo_unlink_lookup_cb, &args, cb_data) == NULL)
    {
        printf("ERROR: in calling lookup from UNLINK function\n");
        return -EINVAL;
    }

    return OP_STATUS_ASYNC;
}

static int
lo_forget(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    decrement_ref_count_db(vfsdev->db, (unsigned long)fsdev_io->u_in.forget.fobject);
    return 0;
}

static int
lo_release(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    decrement_ref_count_db(vfsdev->db, (unsigned long)fsdev_io->u_in.release.fobject);
    return 0;
}

static int
fsdev_nfs_initialize(void)
{
    printf("+=+=+=+=+=+=+=+=  {fsdev_nfs_initialize} FUNCTION CALLED \n");

    return 0;
}

static void
fsdev_nfs_finish(void)
{
    // TO DO ?
}

static int
fsdev_nfs_get_ctx_size(void)
{
    return sizeof(struct nfs_fsdev_io_device);
}

static struct spdk_fsdev_module nfs_fsdev_module = {
    .name = "nfs",
    .module_init = fsdev_nfs_initialize,
    .module_fini = fsdev_nfs_finish,
    .get_ctx_size = fsdev_nfs_get_ctx_size,
};

SPDK_FSDEV_MODULE_REGISTER(nfs, &nfs_fsdev_module);

static int
fsdev_nfs_destruct(void *ctx)
{
    // TO DO ?
    return 0;
}

typedef int (*fsdev_op_handler_func)(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io);

static int
nimp(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
    printf("+=+=+=+=+=+=+=+=  {nimp} FUNCTION CALLED \n");
    return -ENOSYS;
}

static fsdev_op_handler_func handlers[] = {
    [SPDK_FSDEV_IO_MOUNT] = lo_mount,
    [SPDK_FSDEV_IO_UMOUNT] = lo_umount,
    [SPDK_FSDEV_IO_LOOKUP] = lo_lookup,
    [SPDK_FSDEV_IO_FORGET] = lo_forget,
    [SPDK_FSDEV_IO_GETATTR] = lo_getattr,
    [SPDK_FSDEV_IO_SETATTR] = lo_setattr,
    [SPDK_FSDEV_IO_READLINK] = nimp,
    [SPDK_FSDEV_IO_SYMLINK] = nimp,
    [SPDK_FSDEV_IO_MKNOD] = lo_mknod,
    [SPDK_FSDEV_IO_MKDIR] = lo_mkdir,
    [SPDK_FSDEV_IO_UNLINK] = lo_unlink,
    [SPDK_FSDEV_IO_RMDIR] = nimp, // TO DO
    [SPDK_FSDEV_IO_RENAME] = nimp,
    [SPDK_FSDEV_IO_LINK] = nimp,
    [SPDK_FSDEV_IO_OPEN] = lo_open,
    [SPDK_FSDEV_IO_READ] = lo_read,
    [SPDK_FSDEV_IO_WRITE] = lo_write,
    [SPDK_FSDEV_IO_STATFS] = nimp,
    [SPDK_FSDEV_IO_RELEASE] = lo_release,
    [SPDK_FSDEV_IO_FSYNC] = nimp,
    [SPDK_FSDEV_IO_SETXATTR] = nimp,
    [SPDK_FSDEV_IO_GETXATTR] = nimp,
    [SPDK_FSDEV_IO_LISTXATTR] = nimp,
    [SPDK_FSDEV_IO_REMOVEXATTR] = nimp,
    [SPDK_FSDEV_IO_FLUSH] = nimp,
    [SPDK_FSDEV_IO_OPENDIR] = lo_opendir,
    [SPDK_FSDEV_IO_READDIR] = lo_readdir,
    [SPDK_FSDEV_IO_RELEASEDIR] = nimp,
    [SPDK_FSDEV_IO_FSYNCDIR] = nimp,
    [SPDK_FSDEV_IO_FLOCK] = nimp,
    [SPDK_FSDEV_IO_CREATE] = nimp,
    [SPDK_FSDEV_IO_ABORT] = nimp,
    [SPDK_FSDEV_IO_FALLOCATE] = nimp,
    [SPDK_FSDEV_IO_COPY_FILE_RANGE] = nimp,
    [SPDK_FSDEV_IO_SYNCFS] = nimp, // added
    [SPDK_FSDEV_IO_ACCESS] = nimp, // added
    [SPDK_FSDEV_IO_LSEEK] = nimp,  // added
    [SPDK_FSDEV_IO_POLL] = nimp,   // added
    [SPDK_FSDEV_IO_IOCTL] = nimp,  // added
    [SPDK_FSDEV_IO_GETLK] = nimp,  // added
    [SPDK_FSDEV_IO_SETLK] = nimp,  // added
};

const char *opNames[] = {
    "MOUNT",
    "UMOUNT",
    "LOOKUP",
    "FORGET",
    "GETATTR",
    "SETATTR",
    "READLINK",
    "SYMLINK",
    "MKNOD",
    "MKDIR",
    "UNLINK",
    "RMDIR",
    "RENAME",
    "LINK",
    "OPEN",
    "READ",
    "WRITE",
    "STATFS",
    "RELEASE",
    "FSYNC",
    "SETXATTR",
    "GETXATTR",
    "LISTXATTR",
    "REMOVEXATTR",
    "FLUSH",
    "OPENDIR",
    "READDIR",
    "RELEASEDIR",
    "FSYNCDIR",
    "FLOCK",
    "CREATE",
    "ABORT",
    "FALLOCATE",
    "COPY_FILE_RANGE",
    "SYNCFS",
    "ACCESS",
    "LSEEK",
    "POLL",
    "IOCTL",
    "GETLK",
    "SETLK"};

static void
fsdev_nfs_submit_request(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
    enum spdk_fsdev_io_type op = spdk_fsdev_io_get_type(fsdev_io);

    printf("\033[33m+=+=+=+=+=+=+=+=  {fsdev_nfs_submit_request} FUNCTION CALLED and we are calling FUNCTION [%s]\033[0m\n", opNames[op]);

    assert(op >= 0 && op < __SPDK_FSDEV_IO_LAST);

    if (op != SPDK_FSDEV_IO_UNLINK)
    {
        if (fsdev_io->internal.unique > 0xffffffff)
        {
            printf("Error: the xid of the next io request is out of bounds.\n");
            return;
        }
        struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(ch);
        rpc_set_next_xid(nfs_get_rpc_context(vch->nfs), (unsigned int)fsdev_io->internal.unique);
    }
    int status = handlers[op](ch, fsdev_io);

    if (status != OP_STATUS_ASYNC)
    {
        spdk_fsdev_io_complete(fsdev_io, status);
    }
}

static struct spdk_io_channel *
fsdev_nfs_get_io_channel(void *ctx)
{
    printf("+=+=+=+=+=+=+=+=  {fsdev_nfs_get_io_channel} FUNCTION CALLED\n");
    return spdk_get_io_channel(ctx);
}

static void
fsdev_nfs_write_config_json(struct spdk_fsdev *fsdev, struct spdk_json_write_ctx *w)
{
    // TO DO ?
}

static int
fsdev_nfs_reset(void *_ctx, spdk_fsdev_reset_done_cb cb, void *cb_arg)
{
    cb(cb_arg, 0);

    return 0;
}

static const struct spdk_fsdev_fn_table nfs_fn_table = {
    .destruct = fsdev_nfs_destruct,
    .submit_request = fsdev_nfs_submit_request,
    .get_io_channel = fsdev_nfs_get_io_channel,
    .write_config_json = fsdev_nfs_write_config_json,
    .reset = fsdev_nfs_reset,
};

static int
nfs_io_progress_and_poll(void *ctx)
{
    struct nfs_io_channel *ch = ctx;

    ch->pfds[0].fd = nfs_get_fd(ch->nfs);
    ch->pfds[0].events = nfs_which_events(ch->nfs);

    if (poll(&ch->pfds[0], 1, 1) < 0)
    {
        printf("Poll failed");
        return SPDK_POLLER_IDLE;
    }

    if (nfs_service(ch->nfs, ch->pfds[0].revents) < 0)
    {
        printf("nfs_service failed\n");
        exit(10);
    }

    return 1;
}

static int
nfs_io_channel_init_create_cb(void *io_device, void *ctx_buf)
{
    printf("+=+=+=+=+=+=+=+=  {nfs_io_channel_init_create_cb} FUNCTION CALLED \n");

    struct nfs_fsdev *vfsdev = io_device;
    struct nfs_io_channel *vch = ctx_buf;

    vch->nfs = nfs_init_context();
    if (vch->nfs == NULL)
    {
        printf("failed to init context\n");
        exit(10);
    }

    int ret = nfs_mount(vch->nfs, vfsdev->server, vfsdev->export);
    if (ret != 0)
    {
        printf("Failed to start async nfs mount\n");
        exit(10);
    }

    struct nfs_fh3 root_fh3;
    const struct nfs_fh *root_fh = nfs_get_rootfh(vch->nfs);

    printf("\033[38;5;208m"); // Set text color to bright orange
    printf("the value of the root FH is = [");
    for (int i = 0; i < root_fh->len; ++i)
    {
        printf("%c", *(root_fh->val + i));
    }
    printf("]\n");
    printf("\033[0m"); // Reset text color to default

    root_fh3.data.data_val = root_fh->val;
    root_fh3.data.data_len = root_fh->len;

    insert_db(vfsdev->db, (unsigned long)1, &root_fh3);

    vch->poller = SPDK_POLLER_REGISTER(nfs_io_progress_and_poll, vch, 0);

    return 0;
}

static void
nfs_io_channel_destroy_cb(void *io_device, void *ctx_buf)
{
    // TO DO ?
}

int spdk_fsdev_nfs_create(struct spdk_fsdev **fsdev, const char *name)
{
    printf("+=+=+=+=+=+=+=+=  {spdk_fsdev_nfs_create} FUNCTION CALLED \n");

    struct nfs_fsdev *vfsdev;
    vfsdev = calloc(1, sizeof(*vfsdev));
    if (!vfsdev)
    {
        SPDK_ERRLOG("Could not allocate nfs fsdev\n");
        return -ENOMEM;
    }

    vfsdev->server = "127.0.0.1";
    vfsdev->export = "/VIRTUAL";

    const char *filename = "/tmp/dataBase_log.bin";
    unsigned long database_size = 200000;
    vfsdev->db = alloc_init_map_db(filename, database_size);

    printf("finished map init \n");

    vfsdev->fsdev.ctxt = vfsdev;
    vfsdev->fsdev.fn_table = &nfs_fn_table;
    vfsdev->fsdev.module = &nfs_fsdev_module;
    vfsdev->fsdev.name = strdup(name);

    if (!vfsdev->fsdev.name)
    {
        SPDK_ERRLOG("Could not strdup fsdev name: %s\n", name);
        free(vfsdev);
        return -ENOMEM;
    }
    spdk_fsdev_register(&vfsdev->fsdev);

    spdk_io_device_register(vfsdev,
                            nfs_io_channel_init_create_cb, nfs_io_channel_destroy_cb,
                            sizeof(struct nfs_io_channel), "nfs_fsdev");

    *fsdev = &(vfsdev->fsdev);

    return 0;
}

void spdk_fsdev_nfs_delete(const char *name,
                           spdk_delete_nfs_fsdev_complete cb_fn, void *cb_arg)
{
    int rc;

    rc = spdk_fsdev_unregister_by_name(name, &nfs_fsdev_module, cb_fn, cb_arg);
    if (rc != 0)
    {
        cb_fn(cb_arg, rc);
    }

    SPDK_DEBUGLOG(fsdev_nfs, "Deleted nfs filesystem %s\n", name);
}

SPDK_LOG_REGISTER_COMPONENT(fsdev_nfs)
