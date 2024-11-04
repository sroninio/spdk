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
#include <spdk/barrier.h>
#include "c_to_cpp_pipe.h"

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

#define OPEN_CLOSE_STRUCT_REPLY_MAGIC_NUM 0x2244387115
#define INIT_VALUE_XID 0
struct OpenCloseReply
{
    unsigned long header_xid;
    unsigned long expected_ref_count;
    unsigned long file_inode;
    unsigned long magic_number;
    unsigned long suffix_xid;
};

const struct nfs_fh *
nfs_get_rootfh(struct nfs_context *nfs);

struct nfs_fsdev
{
    struct spdk_fsdev fsdev;
    char *server;
    char *export;
    void *db;
    struct OpenCloseReply *open_close_reply_struct;
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

enum UnlinkReplyStatus
{
    NO_REPLY_UNLINK = 1,
    REPLY_UNLINK_SENT = 2,
    REPLY_UNLINK_FAILED = 3
};

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

static bool
lo_insert_to_data_base(void *db, int state, int ref_count, int inode, struct nfs_fh3 *fh)
{
    struct NfsFsdevEntry temp = {0};
    temp.state = state;
    temp.ref_count = ref_count;
    temp.inode_left_key = inode;
    temp.fh_right_key.data.data_len = fh->data.data_len;
    memcpy(temp.fh_right_key.data.data_val, fh->data.data_val, fh->data.data_len);
    return insert_entry(vfsdev->db, &temp, temp.inode_left_key, &temp.fh_right_key);
}

static bool
lo_initialize_new_root_entry_and_insert_to_db(unsigned long inode, const struct nfs_fh *fh, struct nfs_fsdev *vfsdev)
{
    struct NfsFsdevEntry temp_entry = {0};
    temp_entry.inode_left_key = inode;
    temp_entry.ref_count = 0;
    temp_entry.fh_right_key.data.data_len = fh->len;
    memcpy(temp_entry.fh_right_key.data.data_val, fh->val, fh->len);
    temp_entry.state = REGULAR_STATE;
    return insert_entry(vfsdev->db, &temp_entry, inode, &temp_entry.fh_right_key);
}

static void
lo_update_open_close_reply_struct(unsigned long xid, unsigned long inode, unsigned long expected_ref_count, struct OpenCloseReply *ptr)
{
    ptr->header_xid = xid;
    spdk_compiler_barrier();

    ptr->file_inode = inode;
    ptr->expected_ref_count = expected_ref_count;

    spdk_compiler_barrier();
    ptr->suffix_xid = xid;
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
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    unsigned long xid = (unsigned long)fsdev_io->internal.unique;

    if (xid < vfsdev->open_close_reply_struct->suffix_xid)
    {
        printf("Warning: got and old I/O request\n");
        fsdev_io->u_out.open.fhandle = (struct spdk_fsdev_file_handle *)fsdev_io->u_in.open.fobject;
        return 0;
    }

    if (check_if_exist_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.release.fobject) == false)
    {
        printf("Error: trying to open a unknown file\n");
        exit(1);
    }

    struct NfsFsdevEntry temp = get_entry_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.release.fobject);

    if (temp.state == PENDING_DELETION_STATE)
    {
        printf("Error: trying to get new file descriptor for a file that is pending deletion\n");
        return -EINVAL;
    }

    lo_update_open_close_reply_struct(xid, (unsigned long)fsdev_io->u_in.open.fobject,
                                      real_entry->ref_count + 1, vfsdev->open_close_reply_struct);

    spdk_compiler_barrier();

    temp.ref_count++;

    if (!update_entry_by_left(vfsdev->db, &temp, temp.inode_left_key))
    {
        printf("Error: falied at open I/O request - updating the data base \n");
        return -EINVAL;
    }

    fsdev_io->u_out.open.fhandle = (struct spdk_fsdev_file_handle *)fsdev_io->u_in.open.fobject;

    return 0;
}

static void
lo_write_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    printf("+=+=+=+=+=+=+=+=  {lo_write_cb} FUNCTION CALLED \n");

    struct spdk_fsdev_io *fsdev_io = private_data;
    if (status == RPC_STATUS_ERROR)
    {
        printf("Error: write failed with error [%s]\n", (char *)data);
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("Error: write failed \n");
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

    if (check_if_exist_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.write.fhandle) == false)
    {
        printf("Error: trying to write to a none existing file\n");
        exit(1);
    }

    struct NfsFsdevEntry temp = get_entry_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.write.fhandle);
    if (temp.state == PENDING_DELETION_STATE)
    {
        printf("Warning: Trying to make I/O request on inode that is pending deletion\n");
        return -EINVAL;
    }
    const struct iovec *invec = fsdev_io->u_in.write.iov;

    struct WRITE3args args = {0};
    args.file.data.data_len = temp.fh_right_key.data.data_len;
    args.file.data.data_val = temp.fh_right_key.data.data_val;
    args.offset = fsdev_io->u_in.write.offs;
    args.count = fsdev_io->u_in.write.size;
    args.data.data_val = invec[0].iov_base;
    args.data.data_len = fsdev_io->u_in.write.size;

    args.stable = FILE_SYNC;
    /* The choice of stability affects the trade-off between performance and data safety:
       UNSTABLE is fastest but least safe
       FILE_SYNC is slowest but most safe
       DATA_SYNC is a middle ground
    */

    if (rpc_nfs3_write_task(nfs_get_rpc_context(vch->nfs),
                            lo_write_cb, &args, fsdev_io) == NULL)
    {
        printf("Error: in write opertion\n");
        exit(1);
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
        printf("Error: read failed with error [%s]\n", (char *)data);
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("Error: read failed \n");
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    struct READ3res *result = data;

    fsdev_io->u_out.read.data_size = result->READ3res_u.resok.count;

    spdk_fsdev_io_complete(fsdev_io, 0);
}

static int
lo_read(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    printf("+=+=+=+=+=+=+=+=  {lo_read} FUNCTION CALLED \n");

    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);
    struct iovec *outvec = fsdev_io->u_in.read.iov;

    if (check_if_exist_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.read.fhandle) == false)
    {
        printf("Error: trying to read a none existing file\n");
        exit(1);
    }

    struct NfsFsdevEntry temp = get_entry_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.read.fhandle);
    if (temp.state == PENDING_DELETION_STATE)
    {
        printf("Warning: Trying to make I/O request on inode that is pending deletion\n");
        return -EINVAL;
    }

    struct READ3args args = {0};
    args.file.data.data_len = temp.fh_right_key.data.data_len;
    args.file.data.data_val = temp.fh_right_key.data.data_val;
    args.offset = fsdev_io->u_in.read.offs;
    args.count = outvec[0].iov_len;

    if (rpc_nfs3_read_task(nfs_get_rpc_context(vch->nfs), lo_read_cb, outvec[0].iov_base,
                           outvec[0].iov_len, &args, fsdev_io) == NULL)
    {
        printf("Error: in read request \n");
        exit(1);
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
        printf("Error: getattr failed with error [%s]\n", (char *)data);
        exit(1);
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("Error: getattr failed \n");
        exit(1);
    }

    struct GETATTR3res *result = data;
    fattr3 *res = &result->GETATTR3res_u.resok.obj_attributes;
    lo_fill_attr(&fsdev_io->u_out.getattr.attr, res, (unsigned long)fsdev_io->u_in.getattr.fobject);

    spdk_fsdev_io_complete(fsdev_io, 0);
}

static int
lo_getattr(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    printf("+=+=+=+=+=+=+=+=  {lo_getattr} FUNCTION CALLED with inode number [%ld] \n", (unsigned long)fsdev_io->u_in.getattr.fobject);

    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);

    if (check_if_exist_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.getattr.fobject) == false)
    {
        printf("Error: trying to get attributes of none exisiting entry\n");
        exit(1);
    }

    struct NfsFsdevEntry temp = get_entry_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.getattr.fobject);
    if (temp.state == PENDING_DELETION_STATE)
    {
        printf("Warnning: Trying to make I/O request on inode that is pending deletion\n");
        return -EINVAL;
    }

    struct GETATTR3args args = {0};
    args.object.data.data_len = temp.fh_right_key.data.data_len;
    args.object.data.data_val = temp.fh_right_key.data.data_val;

    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);

    if (rpc_nfs3_getattr_task(nfs_get_rpc_context(vch->nfs), lo_getattr_cb, &args, fsdev_io) == NULL)
    {
        printf("Error: in getting attributes \n");
        exit(1);
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

static void
lo_lookup_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    printf("+=+=+=+=+=+=+=+=  {lo_lookup_cb} FUNCTION CALLED \n");

    struct spdk_fsdev_io *fsdev_io = private_data;
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);

    if (status == RPC_STATUS_ERROR)
    {
        printf("Error: LOOKUP failed with error [%s]\n", (char *)data);
        exit(1);
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("Error: LOOKUP failed \n");
        exit(1);
    }
    struct LOOKUP3res *result = data;
    nfsstat3 ret = result->status;
    if (ret != NFS3_OK)
    {
        if (ret == NFS3ERR_NOENT)
        {
            printf("Error: lookup result is NFS3ERR_NOENT \n");
            spdk_fsdev_io_complete(fsdev_io, -ENOENT);
        }
        else
        {
            printf("Error: lookup result is other than OK or NOENT = [%d]\n", ret);
            spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        }
        return;
    }

    struct persistent_nfs_fh3 temp_fh = {0};
    temp_fh.data.data_len = result->LOOKUP3res_u.resok.object.data.data_len;
    memcpy(temp_fh.data.data_val, result->LOOKUP3res_u.resok.object.data.data_val, temp_fh.data.data_len);
    unsigned long inode;

    if (check_if_exist_by_right(vfsdev->db, &temp_fh))
    {
        struct NfsFsdevEntry temp = get_entry_by_right(vfsdev->db, &temp_fh);
        if (temp.state == PENDING_DELETION_STATE)
        {
            printf("Error: Trying to make I/O request on a file that is pending deletion\n");
            exit(1);
        }
        inode = temp.inode_left_key;
    }
    else
    {
        inode = generate_left_key(vfsdev->db);
        if (!lo_insert_to_data_base(vfsdev->db, REGULAR_STATE, 0, inode, &result->LOOKUP3res_u.resok.object))
        {
            printf("Error:  falied at inserting new entry to our data base \n");
            exit(1);
        }
    }

    printf("$$$$$$ WE ARE RETURNNING INODE %ld\n", inode); //

    fsdev_io->u_out.lookup.fobject = (struct spdk_fsdev_file_object *)inode;
    fattr3 *res = &result->LOOKUP3res_u.resok.obj_attributes.post_op_attr_u.attributes;
    lo_fill_attr(&fsdev_io->u_out.lookup.attr, res, inode);

    spdk_fsdev_io_complete(fsdev_io, 0);
}

static int
lo_lookup(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);

    printf("+=+=+=+=+=+=+=+=  {lo_lookup} FUNCTION CALLED fuse_inode = %ld, name=%s\n", (unsigned long)fsdev_io->u_in.lookup.parent_fobject, fsdev_io->u_in.lookup.name);
    fflush(stdout);

    if ((unsigned long)fsdev_io->u_in.lookup.parent_fobject == 0)
    {
        printf("\033[1;31mError: WE ARE CALLING LOOK UP WITH PARENT INODE = 0 !!\033[0m\n");
        exit(1);
    }

    if (check_if_exist_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.lookup.parent_fobject) == false)
    {
        printf("Error: parent directory none known - can lookup child\n");
        exit(1);
    }

    struct NfsFsdevEntry temp = get_entry_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.lookup.parent_fobject);
    if (temp.state == PENDING_DELETION_STATE)
    {
        printf("Warning: Trying to make I/O request on a file with parent directory that is pending deletion\n");
        return -EINVAL;
    }

    struct LOOKUP3args args = {0};
    args.what.dir.data.data_len = temp.fh_right_key.data.data_len;
    args.what.dir.data.data_val = temp.fh_right_key.data.data_val;
    args.what.name = fsdev_io->u_in.lookup.name;

    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);

    if (rpc_nfs3_lookup_task(nfs_get_rpc_context(vch->nfs), lo_lookup_cb, &args, fsdev_io) == NULL)
    {
        printf("Error: in calling lookup\n");
        exit(1);
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
        printf("Error: READDIR failed with error [%s]\n", (char *)data);
        exit(1);
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("Error: READDIR failed \n");
        exit(1);
    }

    struct READDIRPLUS3res *res = data;
    dirlistplus3 list_head = res->READDIRPLUS3res_u.resok.reply;
    entryplus3 *curr_entry = list_head.entries;
    while (curr_entry != NULL)
    {
        struct persistent_nfs_fh3 temp_fh = {0};
        temp_fh.data.data_len = curr_entry->name_handle.post_op_fh3_u.handle.data.data_len;
        memcpy(temp_fh.data.data_val, curr_entry->name_handle.post_op_fh3_u.handle.data.data_val, temp_fh.data.data_len);

        unsigned long inode;

        if (check_if_exist_by_right(vfsdev->db, &temp_fh))
        {
            struct NfsFsdevEntry temp = get_entry_by_right(vfsdev->db, &temp_fh);
            inode = temp.inode_left_key;
        }
        else
        {
            inode = generate_left_key(vfsdev->db);
            if (!lo_insert_to_data_base(vfsdev->db, REGULAR_STATE, 0, inode, &curr_entry->name_handle.post_op_fh3_u.handle))
            {
                printf("Error: falied at inserting new entry to our data base \n");
                exit(1);
            }
        }

        // prints that will be deleted later on to avoid overhead
        printf("READDIR ENTRY : NAME=[%s] AND GIVEN INODE [%ld]\n", curr_entry->name, inode);
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
        lo_fill_attr(&fsdev_io->u_out.readdir.attr, &curr_entry->name_attributes.post_op_attr_u.attributes, inode);
        fsdev_io->u_out.readdir.fobject = (struct spdk_fsdev_file_object *)inode;
        fsdev_io->u_in.readdir.entry_cb_fn(fsdev_io, fsdev_io->internal.cb_arg, &forget);
        curr_entry = curr_entry->nextentry;
    }

    spdk_fsdev_io_complete(fsdev_io, 0);
}

static int
lo_readdir(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    printf("+=+=+=+=+=+=+=+=  {lo_readdir} FUNCTION CALLED for inode number [%ld]\n", (unsigned long)fsdev_io->u_in.readdir.fobject);
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);

    if (check_if_exist_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.readdir.fobject) == false)
    {
        printf("Error: none existing directory\n");
        exit(1);
    }

    struct NfsFsdevEntry temp = get_entry_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.readdir.fobject);
    if (temp.state == PENDING_DELETION_STATE)
    {
        printf("Error: Trying to make I/O request on inode that is pending deletion\n");
        return -EINVAL;
    }

    struct READDIRPLUS3args args = {0};
    args.dir.data.data_len = temp.fh_right_key.data.data_len;
    args.dir.data.data_val = temp.fh_right_key.data.data_val;
    args.cookie = fsdev_io->u_in.readdir.offset;
    args.dircount = 1000000;
    args.maxcount = 1000000;

    if (rpc_nfs3_readdirplus_task(nfs_get_rpc_context(vch->nfs), lo_readdir_cb, &args, fsdev_io) == NULL)
    {
        printf("Error: in calling readdir\n");
        exit(1);
    }

    return OP_STATUS_ASYNC;
}

static void
lo_mknod_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    printf("+=+=+=+=+=+=+=+=  {lo_mknod_cb} FUNCTION CALLED \n");

    struct spdk_fsdev_io *fsdev_io = private_data;
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    if (status == RPC_STATUS_ERROR)
    {
        printf("Error: lo_create failed with error [%s]\n", (char *)data);
        exit(1);
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("Error: lo_create failed \n");
        exit(1);
    }
    struct CREATE3res *result = data;
    if (result->status != NFS3_OK)
    {
        printf("Error: create returned error [%d]\n", result->status);
        exit(1);
    }

    struct persistent_nfs_fh3 temp_fh = {0};
    temp_fh.data.data_len = result->CREATE3res_u.resok.obj.post_op_fh3_u.handle.data.data_len;
    memcpy(temp_fh.data.data_val, result->CREATE3res_u.resok.obj.post_op_fh3_u.handle.data.data_val, temp_fh.data.data_len);

    if (check_if_exist_by_right(vfsdev->db, &temp_fh))
    {
        struct NfsFsdevEntry real_entry = get_entry_by_right(vfsdev->db, &temp_fh);

        if (real_entry.fh_right_key.data.data_len == temp_fh.data.data_len && memcmp(real_entry.fh_right_key.data.data_val, temp_fh.data.data_val, temp_fh.data.data_len) == 0)
        {
            printf("Warning: reply of mknod\n");
            fattr3 *res = &result->CREATE3res_u.resok.obj_attributes.post_op_attr_u.attributes;
            lo_fill_attr(&fsdev_io->u_out.mknod.attr, res, real_entry.inode_left_key);
            fsdev_io->u_out.mknod.fobject = (struct spdk_fsdev_file_object *)real_entry.inode_left_key;
            spdk_fsdev_io_complete(fsdev_io, 0);
        }

        if (!remove_entry_by_right(vfsdev->db, &temp_fh))
        {
            printf("Error: problem deleting an entry from the data base\n");
            exit(1);
        }
    }

    unsigned long new_inode = generate_left_key(vfsdev->db);

    if (!lo_insert_to_data_base(vfsdev->db, REGULAR_STATE, 0, new_inode, &result->CREATE3res_u.resok.obj.post_op_fh3_u.handle))
    {
        printf("Error: falied at inserting new entry to our data base \n");
        exit(1);
    }

    fattr3 *res = &result->CREATE3res_u.resok.obj_attributes.post_op_attr_u.attributes;
    lo_fill_attr(&fsdev_io->u_out.mknod.attr, res, new_inode);
    fsdev_io->u_out.mknod.fobject = (struct spdk_fsdev_file_object *)new_inode;

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

        if (check_if_exist_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.mknod.parent_fobject) == false)
        {
            printf("Error: trying to create a new file in a directory that is pending deletion\n");
            exit(1);
        }

        struct NfsFsdevEntry temp = get_entry_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.mknod.parent_fobject);

        assert(temp.state != PENDING_DELETION_STATE);

        struct CREATE3args args = {0};
        args.where.dir.data.data_len = temp.fh_right_key.data.data_len;
        args.where.dir.data.data_val = temp.fh_right_key.data.data_val;
        args.where.name = fsdev_io->u_in.mknod.name;
        args.how.mode = UNCHECKED; // Or GUARDED, or EXCLUSIVE (UNCHECKED mode creates the file regardless of whether it exists. GUARDED fails if the file exists. EXCLUSIVE is for atomic file creation.)
        args.how.createhow3_u.obj_attributes.mode.set_it = 1;
        args.how.createhow3_u.obj_attributes.mode.set_mode3_u.mode = fsdev_io->u_in.mknod.mode & 0777;
        args.how.createhow3_u.obj_attributes.uid.set_it = 1;
        args.how.createhow3_u.obj_attributes.uid.set_uid3_u.uid = fsdev_io->u_in.mknod.euid;
        args.how.createhow3_u.obj_attributes.gid.set_it = 1;
        args.how.createhow3_u.obj_attributes.gid.set_gid3_u.gid = fsdev_io->u_in.mknod.egid;

        if (rpc_nfs3_create_task(nfs_get_rpc_context(vch->nfs), lo_mknod_cb, &args, fsdev_io) == NULL)
        {
            printf("Error: in calling create\n");
            return -EINVAL;
        }
        return OP_STATUS_ASYNC;
        break;
    default: // all sort of links
        printf("Error: Unexpected file type in mode: %o\n", fsdev_io->u_in.mknod.mode);
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
        printf("Error: lo_mkdir failed with error [%s]\n", (char *)data);
        exit(1);
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("Error: lo_mkdir failed \n");
        exit(1);
    }

    struct MKDIR3res *result = data;
    if (result->status != NFS3_OK)
    {
        printf("Error: problem in mkdir error code =[%d]\n", result->status);
        exit(1);
    }

    if (result->MKDIR3res_u.resok.obj.post_op_fh3_u.handle.data.data_len > MAX_FH_DATA_LEN)
    {
        printf("Error: file handle returned in lookup too long\n");
        exit(1);
    }

    struct persistent_nfs_fh3 temp_fh = {0};
    temp_fh.data.data_len = result->MKDIR3res_u.resok.obj.post_op_fh3_u.handle.data.data_len;
    memcpy(temp_fh.data.data_val, result->MKDIR3res_u.resok.obj.post_op_fh3_u.handle.data.data_val, temp_fh.data.data_len);

    if (check_if_exist_by_right(vfsdev->db, &temp_fh))
    {
        printf("Error: this directory already exist \n"); // the case that is pending deletion is also here.
        exit(1);
    }

    unsigned long new_inode = generate_left_key(vfsdev->db);

    if (!lo_insert_to_data_base(vfsdev->db, REGULAR_STATE, 0, new_inode, &result->MKDIR3res_u.resok.obj.post_op_fh3_u.handle))
    {
        printf("Error: falied at inserting into data base new entry for a new directory \n");
        exit(1);
    }

    fattr3 *res = &result->MKDIR3res_u.resok.obj_attributes.post_op_attr_u.attributes;
    lo_fill_attr(&fsdev_io->u_out.mkdir.attr, res, new_inode);
    fsdev_io->u_out.mkdir.fobject = (struct spdk_fsdev_file_object *)new_inode;
    spdk_fsdev_io_complete(fsdev_io, 0);
}

static int
lo_mkdir(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    printf("+=+=+=+=+=+=+=+=  {lo_mkdir} FUNCTION CALLED \n");

    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);

    struct MKDIR3args args = {0};

    if (check_if_exist_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.mkdir.parent_fobject) == false)
    {
        printf("Error: Trying to create a directory in a not known parent directory\n");
        exit(1);
    }

    struct NfsFsdevEntry temp = get_entry_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.mkdir.parent_fobject);
    if (temp.state == PENDING_DELETION_STATE)
    {
        printf("Warnning: Trying to make I/O request on inode that his parent is pending deletion\n");
        return -EINVAL;
    }

    args.where.dir.data.data_len = temp.fh_right_key.data.data_len;
    args.where.dir.data.data_val = temp.fh_right_key.data.data_val;

    args.where.name = fsdev_io->u_in.mkdir.name;
    args.attributes.gid.set_it = 1;
    args.attributes.gid.set_gid3_u.gid = fsdev_io->u_in.mkdir.egid;
    args.attributes.uid.set_it = 1;
    args.attributes.uid.set_uid3_u.uid = fsdev_io->u_in.mkdir.euid;
    args.attributes.mode.set_it = 1;
    args.attributes.mode.set_mode3_u.mode = fsdev_io->u_in.mkdir.mode & 0777;

    if (rpc_nfs3_mkdir_task(nfs_get_rpc_context(vch->nfs), lo_mkdir_cb, &args, fsdev_io) == NULL)
    {
        printf("Error: in calling mkdir\n");
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
        printf("Error: setattr failed with error [%s]\n", (char *)data);
        exit(1);
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("Error: setattr failed \n");
        exit(1);
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
    printf("+=+=+=+=+=+=+=+=  {lo_setattr} FUNCTION CALLED with inode number [%ld] \n", (unsigned long)fsdev_io->u_in.setattr.fobject);
    struct spdk_fsdev_file_attr *attr = &fsdev_io->u_in.setattr.attr;

    if (check_if_exist_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.setattr.fobject) == false)
    {
        printf("Error: file is not existing \n");
        exit(1);
    }

    struct NfsFsdevEntry temp_entry = get_entry_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.setattr.fobject);
    if (temp_entry->state == PENDING_DELETION_STATE)
    {
        printf("Warning: Trying to make I/O request on inode that is pending deletion\n");
        return -EINVAL;
    }

    struct SETATTR3args args = {0};
    args.object.data.data_len = temp_entry.fh_right_key.data.data_len;
    args.object.data.data_val = temp_entry.fh_right_key.data.data_val;

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
        printf("Error: in setting attributes \n");
        return -EINVAL;
    }

    return OP_STATUS_ASYNC;
}

static struct fsdev_and_fsdev_io *
lo_allocate_and_initialize_cb_data(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    struct fsdev_and_fsdev_io *cb_data = calloc(1, sizeof(struct fsdev_and_fsdev_io));
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

    struct fsdev_and_fsdev_io *cb_data = private_data;
    struct spdk_fsdev_io *fsdev_io = cb_data->fsdev_io;

    if (status == RPC_STATUS_ERROR)
    {
        printf("Error: unlink failed with error [%s]\n", (char *)data);
        free(cb_data);
        exit(1);
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("Error: unlink failed \n");
        free(cb_data);
        exit(1);
    }

    if (!remove_entry_by_left(cb_data->vfsdev->db, cb_data->key))
    {
        printf("Error: falied in removing entry from data base\n");
        free(cb_data);
        exit(1);
    }

    free(cb_data);
    spdk_fsdev_io_complete(fsdev_io, 0);
}

static void
lo_unlink_lookup_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    printf("+=+=+=+=+=+=+=+=  {lo_unlink_lookup_cb} FUNCTION CALLED \n");
    fflush(stdout);

    struct fsdev_and_fsdev_io *cb_data = private_data;
    struct spdk_io_channel *_ch = cb_data->_ch;
    struct spdk_fsdev_io *fsdev_io = cb_data->fsdev_io;
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);

    if (status == RPC_STATUS_ERROR)
    {
        printf("Error: LOOKUP FROM UNLINK failed with error [%s]\n", (char *)data);
        free(cb_data);
        exit(1);
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("Error: LOOKUP FROM UNLINK failed \n");
        free(cb_data);
        exit(1);
    }
    struct LOOKUP3res *result = data;
    nfsstat3 ret = result->status;
    if (ret != NFS3_OK)
    {
        if (ret == NFS3ERR_NOENT)
        {
            printf("Error: lookup result is NFS3ERR_NOENT - tried to delete a none existing file \n");
        }
        else
        {
            printf("Error: lookup result is other than OK or NOENT = [%d]\n", ret);
        }
        free(cb_data);
        exit(1);
    }

    struct nfs_fh3 *fh = &(result->LOOKUP3res_u.resok.object);

    struct persistent_nfs_fh3 temp = {0};
    temp.data.data_len = fh.data.data_len;
    memcpy(temp.data.data_val, fh.data.data_val, temp.data.data_len);

    unsigned long ref_count = 0;
    struct NfsFsdevEntry temp_entry = {0};
    if (check_if_exist_by_right(vfsdev->db, &temp))
    {
        temp_entry = get_entry_by_right(vfsdev->db, &temp);
        temp_entry.state = PENDING_DELETION_STATE;

        if (!update_entry_by_left(vfsdev->db, &temp_entry, temp_entry.inode_left_key))
        {
            printf("Error: Not been able to update entry\n");
            free(cb_data);
            exit(1);
        }
        cb_data->key = temp_entry.inode_left_key;
        ref_count = temp_entry.ref_count;
    }
    else
    {
        unsigned long new_inode = generate_left_key(vfsdev->db);
        if (lo_insert_to_data_base(vfsdev->db, PENDING_DELETION_STATE, 0, new_inode, fh) == false)
        {
            printf("Error: falied in inserting to the map.\n");
            free(cb_data);
            exit(1);
        }
        cb_data->key = new_inode;
    }

    if (ref_count != 0)
    {
        printf("Warning: Trying to UNLINK a file that has positive refrence count this io request will be delayed...\n");

        strcpy(temp_entry.reply_unlink_params.name, fsdev_io->u_in.unlink.name);
        if (!update_entry_by_left(vfsdev->db, &temp_entry, temp_entry.inode_left_key))
        {
            printf("Error: Not been able to update entry\n");
            free(cb_data);
            exit(1);
        }

        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }

    if (check_if_exist_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.unlink.parent_fobject) == false)
    {
        printf("Error: parent entry in the map removed.\n");
        free(cb_data);
        exit(1);
    }

    struct NfsFsdevEntry parent_temp_entry = get_entry_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.unlink.parent_fobject);
    struct REMOVE3args args = {0};
    args.object.dir.data.data_len = parent_temp_entry.fh_right_key.data.data_len;
    args.object.dir.data.data_val = parent_temp_entry.fh_right_key.data.data_val;
    args.object.name = fsdev_io->u_in.unlink.name;

    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);
    rpc_set_next_xid(nfs_get_rpc_context(vch->nfs), (unsigned int)(fsdev_io->internal.unique));

    if (rpc_nfs3_remove_task(nfs_get_rpc_context(vch->nfs), lo_unlink_cb, &args, cb_data) == NULL)
    {
        printf("Error: in unlinking a file \n");
        free(cb_data);
        exit(1);
    }
}

static int
lo_unlink(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);

    if ((unsigned long)fsdev_io->u_in.unlink.parent_fobject == 0)
    {
        printf("\033[1;31mError: WE ARE CALLING LOOK UP WITH PARENT INODE = 0 !! \n Trying to delete root directory \033[0m\n");
        return -EINVAL;
    }

    if (check_if_exist_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.unlink.parent_fobject) == false)
    {
        printf("Error: trying to delete a file that his parent is not in the map");
        exit(1);
    }

    if (strlen(fsdev_io->u_in.unlink.name) + 1 > MAX_FILE_NAME)
    {
        printf("Error: file name is too long = [%ld]\n", fsdev_io->u_in.unlink.name);
        exit(1);
    }

    struct NfsFsdevEntry temp_parent_struct = get_entry_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.unlink.parent_fobject);

    if (temp.state == PENDING_DELETION_STATE)
    {
        printf("Error: Trying to delete a file that his parent is already pending deletion\n");
        exit(1);
    }

    struct LOOKUP3args args = {0};
    args.what.dir.data.data_val = temp.fh_right_key.data.data_val;
    args.what.dir.data.data_len = temp.fh_right_key.data.data_len;
    args.what.name = fsdev_io->u_in.unlink.name;

    struct fsdev_and_fsdev_io *cb_data = lo_allocate_and_initialize_cb_data(_ch, fsdev_io);

    unsigned long xid = (unsigned int)(fsdev_io->internal.unique);

    if (xid + XID_OFFSET > 0xffffffff)
    {
        printf("Error: xid out of bounds\n");
        exit(1);
    }

    rpc_set_next_xid(nfs_get_rpc_context(vch->nfs), (unsigned int)(xid + (unsigned long)XID_OFFSET));

    if (rpc_nfs3_lookup_task(nfs_get_rpc_context(vch->nfs), lo_unlink_lookup_cb, &args, cb_data) == NULL)
    {
        printf("Error: in calling lookup from UNLINK function\n");
        exit(1);
    }

    return OP_STATUS_ASYNC;
}

static int
lo_forget(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    return 0;
}

static void
lo_reply_unlink_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    printf("+=+=+=+=+=+=+=+=  {lo_reply_unlink_cb} FUNCTION CALLED \n");
    fflush(stdout);

    struct spdk_fsdev_io *fsdev_io = private_data;

    if (status == RPC_STATUS_ERROR)
    {
        printf("Error: unlink failed with error [%s]\n", (char *)data);
        exit(1);
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("Error: unlink failed \n");
        exit(1);
    }
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    if (!remove_entry_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.release.fobject))
    {
        printf("Error: falied at removing entry from data base in unlink reply  \n");
        exit(1);
    }
    spdk_fsdev_io_complete(fsdev_io, 0);
}

static int
lo_release(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);

    unsigned long xid = (unsigned long)fsdev_io->internal.unique;

    if (xid < vfsdev->open_close_reply_struct->suffix_xid)
    {
        printf("Warning: got and old I/O request\n");
        return 0;
    }

    if (check_if_exist_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.release.fobject) == false)
    {
        printf("Error: trying to close fd that don't have an entry in data base \n");
        exit(1);
    }

    struct NfsFsdevEntry temp = get_entry_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.release.fobject);
    temp.ref_count--;

    lo_update_open_close_reply_struct(xid, (unsigned long)fsdev_io->u_in.release.fobject,
                                      real_entry.ref_count, vfsdev->open_close_reply_struct);

    spdk_compiler_barrier();

    if (temp.ref_count == 0 && temp.state == PENDING_DELETION_STATE)
    {
        struct REMOVE3args args = {0};
        args.object.dir.data.data_val = temp.reply_unlink_params.parent_fh.data.data_val;
        args.object.dir.data.data_len = temp.reply_unlink_params.parent_fh.data.data_len;
        args.object.name = temp.reply_unlink_params.name;

        struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);

        if (rpc_nfs3_remove_task(nfs_get_rpc_context(vch->nfs), lo_reply_unlink_cb, &args, fsdev_io) == NULL) // we are sending this with the same xid (of forget/release). (?)
        {
            printf("Error: in unlinking (reply) a file \n");
            exit(1);
        }

        return OP_STATUS_ASYNC;
    }

    if (!update_entry_by_left(vfsdev->db, &temp, temp.inode_left_key))
    {
        printf("Error: falied at release I/O request - updating the data base \n");
        return exit(1);
    }

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
    [SPDK_FSDEV_IO_RMDIR] = nimp,
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
        unsigned int xid = (unsigned int)fsdev_io->internal.unique;
        assert(xid <= 0xffffffff);
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

    if (!lo_initialize_new_root_entry_and_insert_to_db(1, nfs_get_rootfh(vch->nfs), vfsdev))
    {
        printf("Error: failed in inserting root file handle into map\n");
        exit(-1);
    }

    vch->poller = SPDK_POLLER_REGISTER(nfs_io_progress_and_poll, vch, 0);

    return 0;
}

static void
nfs_io_channel_destroy_cb(void *io_device, void *ctx_buf)
{
    // TO DO ?
}

static void
lo_initilize_open_close_reply_struct(struct OpenCloseReply *open_close_reply_struct)
{
    open_close_reply_struct->header_xid = INIT_VALUE_XID;
    open_close_reply_struct->suffix_xid = INIT_VALUE_XID;
    spdk_compiler_barrier();
    open_close_reply_struct->magic_number = OPEN_CLOSE_STRUCT_REPLY_MAGIC_NUM;
}

static void
lo_restore_open_close_reply_struct(struct OpenCloseReply *open_close_reply_struct, int fd, struct nfs_fsdev *vfsdev)
{
    if (open_close_reply_struct->header_xid == open_close_reply_struct->suffix_xid)
    {
        if (check_if_exist_by_left(vfsdev->db, open_close_reply_struct->file_inode) == false)
        {
            printf("Warning: we are in recovery but the operation is no longer needed cause the entry is not in the data structure.\n");
            return;
        }
        struct NfsFsdevEntry temp = get_entry_by_left(vfsdev->db, open_close_reply_struct->file_inode);
        temp.ref_count = open_close_reply_struct->expected_ref_count;
        if (!update_entry_by_left(vfsdev->db, &temp, open_close_reply_struct->file_inode))
        {
            printf("Error: falied at reply of close/open I/O command\n");
            exit(1);
        }
    }
}

static struct OpenCloseReply *
lo_allocate_and_init_open_close_reply_struct(char *filename, struct nfs_fsdev *vfsdev)
{
    int fd = open(filename, O_RDWR | O_CREAT, 0666);
    if (fd == -1)
    {
        printf("Error: in opening file");
        exit(1);
    }

    size_t full_size = sizeof(struct OpenCloseReply);
    if (ftruncate(fd, full_size) == -1)
    {
        printf("Error: setting file size\n");
        close(fd);
        exit(1);
    }

    struct OpenCloseReply *open_close_reply_struct = mmap(NULL, full_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (open_close_reply_struct == MAP_FAILED)
    {
        printf("Error: error mapping file");
        close(fd);
        exit(1);
    }

    if (open_close_reply_struct->magic_number != OPEN_CLOSE_STRUCT_REPLY_MAGIC_NUM)
    {
        lo_initilize_open_close_reply_struct(open_close_reply_struct);
    }
    else
    {
        lo_restore_open_close_reply_struct(open_close_reply_struct, fd, vfsdev);
    }
    spdk_compiler_barrier();
    return open_close_reply_struct;
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

    char *filename = "/tmp/dataBase_log.bin";
    char *filename_reply_open_close = "/tmp/reply_open_close_log.bin";

    vfsdev->db = allocate_and_init_map(filename);

    vfsdev->open_close_reply_struct = lo_allocate_and_init_open_close_reply_struct(filename_reply_open_close, vfsdev);

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
