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
#include "mymap.h"
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

#define ST_ATIM_NSEC(stbuf) ((stbuf)->st_atim.tv_nsec)
#define ST_CTIM_NSEC(stbuf) ((stbuf)->st_ctim.tv_nsec)
#define ST_MTIM_NSEC(stbuf) ((stbuf)->st_mtim.tv_nsec)
#define ST_ATIM_NSEC_SET(stbuf, val) (stbuf)->st_atim.tv_nsec = (val)
#define ST_CTIM_NSEC_SET(stbuf, val) (stbuf)->st_ctim.tv_nsec = (val)
#define ST_MTIM_NSEC_SET(stbuf, val) (stbuf)->st_mtim.tv_nsec = (val)
#define INVALIDINODE 16

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

unsigned long global_key = 17;

const struct nfs_fh *
nfs_get_rootfh(struct nfs_context *nfs);

struct nfs_fsdev
{
    struct spdk_fsdev fsdev;
    char *server;
    char *export;
    void *map;
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
        // Handle unexpected file type
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

static unsigned long
generate_new_key(void)
{
    printf("\033[94mINCREMENITNG INODE GLOBAL COUNTER !!! before (also return value) [[%ld]]\033[0m\n", global_key);
    return global_key++;
}

static unsigned long
inode_of_filehandle_if_exist(void *map, struct nfs_fh3 *fh) // if not exist we return 16 - unused inode number
{
    // iterate on all the map and check if this exist
    // NOTE - IF THERE ISN'T SUCH AN ENTRY WITH A GIVEN KEY - THE MAP WILL AUTOMATICALLY CREATE SUCH -
    // THIS COULD BE A MAJOR BUG - CAUSE THERE WILL BE GARBAGE VALUES IN THE MAP !!
    // FOR NOW - WE ARN'T REMOVING NODES FROM THE MAP SO THIS IS OK FOR NOW ONLY !!!!
    // SHOULD ADD AN OPTION TO CHECK IF A KEY IS IN THE MAP WITHOUT MAKING A NEW ENTRY !
    unsigned long i = 17;
    for (i = 17; i < global_key; ++i)
    {
        printf("we are in loop 1 \n"); //
        struct nfs_fh3 *curr_fh = my_get(map, i);
        bool charsE = true;
        if (curr_fh->data.data_len != fh->data.data_len)
        {
            continue;
        }
        for (unsigned long j = 0; j < fh->data.data_len; j++)
        {
            if (curr_fh->data.data_val[j] != fh->data.data_val[j])
            {
                charsE = false;
                break;
            }
        }
        if (charsE)
        {
            return i;
        }
    }
    return 16;
}

static int
lo_open(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
    printf("+=+=+=+=+=+=+=+=  {lo_open} FUNCTION CALLED \n");
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
    struct nfs_fh3 *fh = my_get(vfsdev->map, inode_key);

    size_t size = fsdev_io->u_in.write.size;
    uint64_t offs = fsdev_io->u_in.write.offs;
    const struct iovec *invec = fsdev_io->u_in.write.iov;
    uint32_t incnt = fsdev_io->u_in.write.iovcnt;

    if (incnt != 1)
    {
        printf("buffer is splitted\n"); // we should check what this is ?!??
        return -EINVAL;
    }

    struct WRITE3args args = {0};
    args.file = *fh;
    args.offset = offs;
    args.count = size;
    args.data.data_val = invec[0].iov_base;
    args.data.data_len = invec[0].iov_len;

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
    struct nfs_fh3 *fh = my_get(vfsdev->map, inode_key);

    struct iovec *outvec = fsdev_io->u_in.read.iov;
    // uint32_t outcnt = fsdev_io->u_in.read.iovcnt;
    // size_t count = fsdev_io->u_in.read.size;
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
    // fflush(stdout); //

    // if (fsdev_io->u_in.getattr.fhandle != (struct spdk_fsdev_file_handle *)fsdev_io->u_in.getattr.fobject) // i think i should delete this. not sure though
    // {
    //     fsdev_io->u_in.getattr.fhandle = (struct spdk_fsdev_file_handle *)fsdev_io->u_in.getattr.fobject;
    // }

    struct GETATTR3args args = {0};

    struct nfs_fh3 *nfsfh = my_get(vfsdev->map, key);

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

static void lo_lookup_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
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
    int i = inode_of_filehandle_if_exist(vfsdev->map, fh);
    bool is_exist = (i != INVALIDINODE) ? true : false;
    unsigned long new_key;
    if (is_exist)
    {
        new_key = i;
    }
    else
    {
        new_key = generate_new_key();
        my_insert(vfsdev->map, new_key, &(result->LOOKUP3res_u.resok.object));
    }
    printf("$$$$$$ WE ARE RETURNNING INDOE %ld\n", new_key); //

    fsdev_io->u_out.lookup.fobject = (struct spdk_fsdev_file_object *)new_key;
    fattr3 *res = &result->LOOKUP3res_u.resok.obj_attributes.post_op_attr_u.attributes;
    lo_fill_attr(&fsdev_io->u_out.lookup.attr, res, new_key);

    spdk_fsdev_io_complete(fsdev_io, 0);
}

static void
lo_lookuproot_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    printf("+=+=+=+=+=+=+=+=  {lo_lookuproot_cb} FUNCTION CALLED \n");
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
    lo_fill_attr(&fsdev_io->u_out.lookup.attr, res, 1);
    fsdev_io->u_out.lookup.fobject = (struct spdk_fsdev_file_object *)(1);
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
        fsdev_io->u_out.lookup.fobject = (struct spdk_fsdev_file_object *)(1);

        struct GETATTR3args args = {0};
        struct nfs_fh3 *nfsfh = my_get(vfsdev->map, 1);

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
        if (rpc_nfs3_getattr_task(nfs_get_rpc_context(vch->nfs), lo_lookuproot_cb, &args, fsdev_io) == NULL)
        {
            printf("error in getting attributes \n");
            return -EINVAL;
        }

        return OP_STATUS_ASYNC;
    }

    struct nfs_fh3 *nfsfh_parent = my_get(vfsdev->map, key_parent);
    if (nfsfh_parent->data.data_len == 0)
    {
        printf("Not Existing FH for fuse inode %ld", key_parent);
        return -EINVAL;
    }

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
        // if (curr_entry->name[0] == '.' && curr_entry->name[1] == '0' && fsdev_io->u_in.readdir.fobject == 1)
        // {
        //     curr_entry = curr_entry->nextentry;

        //     continue;
        // }
        unsigned long new_key;
        bool is_exist = false;
        unsigned long i = inode_of_filehandle_if_exist(vfsdev->map, &(curr_entry->name_handle.post_op_fh3_u.handle));
        is_exist = (i != INVALIDINODE) ? true : false;
        if (is_exist)
        {
            new_key = i;
        }
        else
        {
            new_key = generate_new_key();
            my_insert(vfsdev->map, new_key, &(curr_entry->name_handle.post_op_fh3_u.handle));
        }
        printf("READDIR ENTRY : NAME=[%s] AND GIVEN INODE [%ld]\n", curr_entry->name, new_key);
        printf("ENTRY DATA:   DATA_LEN =[%d], DATA_VAL =[",
               curr_entry->name_handle.post_op_fh3_u.handle.data.data_len);
        for (unsigned long j = 0; j < curr_entry->name_handle.post_op_fh3_u.handle.data.data_len; j++)
        {
            printf("%c", curr_entry->name_handle.post_op_fh3_u.handle.data.data_val[j]);
        }
        printf("]\n");
        //
        fsdev_io->u_out.readdir.name = curr_entry->name;
        fsdev_io->u_out.readdir.offset = curr_entry->cookie;
        lo_fill_attr(&fsdev_io->u_out.readdir.attr, &curr_entry->name_attributes.post_op_attr_u.attributes, new_key);
        fsdev_io->u_out.readdir.fobject = (struct spdk_fsdev_file_object *)new_key;
        fsdev_io->u_in.readdir.entry_cb_fn(fsdev_io, fsdev_io->internal.cb_arg);
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
    struct nfs_fh3 *nfsfh = my_get(vfsdev->map, key);
    printf("+=+=+=+=+=+=+=+=  {lo_readdir} FUNCTION CALLED for inode number [%ld]\n", key);

    struct READDIRPLUS3args args = {0};
    args.dir = *nfsfh;
    args.cookie = fsdev_io->u_in.readdir.offset;
    // args.cookieverf = 0; // what should i put in this field ??? we are getting this field in the call back
    // should we keep it in the map also ??
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

    unsigned long new_key = generate_new_key(); // should we check if this file already exist ? can it be ?
    my_insert(vfsdev->map, new_key, &result->CREATE3res_u.resok.obj.post_op_fh3_u.handle);

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

    // Determine the file type (we can also extract it from major+minor )
    switch (fsdev_io->u_in.mknod.mode & 0170000) // 0170000 is the mask for file type bits
    {
    case 0100000: // regular files
        // printf("regular file called mknod instead of create !! \n"); // delete later
        struct CREATE3args args2 = {0};
        args2.where.dir = *my_get(vfsdev->map, (unsigned long)fsdev_io->u_in.mknod.parent_fobject);
        args2.where.name = fsdev_io->u_in.mknod.name;
        args2.how.mode = UNCHECKED; // Or GUARDED, or EXCLUSIVE (UNCHECKED mode creates the file regardless
                                    // of whether it exists. GUARDED fails if the file exists. EXCLUSIVE is for atomic file creation.)
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

/*
static int
lo_mknod(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    printf("+=+=+=+=+=+=+=+=  {lo_mknod} FUNCTION CALLED \n");

    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);

    struct MKNOD3args args = {0};
    args.where.dir = *my_get(vfsdev->map, (unsigned long)fsdev_io->u_in.mknod.parent_fobject);
    args.where.name = fsdev_io->u_in.mknod.name;

    unsigned long rdev = fsdev_io->u_in.mknod.rdev;
    unsigned int major = (rdev >> 8) & 0xfff;
    unsigned int minor = (rdev & 0xff) | ((rdev >> 12) & 0xfff00);

    // Determine the file type (we can also extract it from major+minor )
    switch (fsdev_io->u_in.mknod.mode & 0170000) // 0170000 is the mask for file type bits
    {
    case 0060000:
        args.what.type = NF3BLK; // Block special
        args.what.mknoddata3_u.blk_device.dev_attributes.gid.set_it = 1;
        args.what.mknoddata3_u.blk_device.dev_attributes.gid.set_gid3_u.gid = fsdev_io->u_in.mknod.egid;
        args.what.mknoddata3_u.blk_device.dev_attributes.uid.set_it = 1;
        args.what.mknoddata3_u.blk_device.dev_attributes.uid.set_uid3_u.uid = fsdev_io->u_in.mknod.euid;
        args.what.mknoddata3_u.blk_device.dev_attributes.mode.set_it = 1;
        args.what.mknoddata3_u.blk_device.dev_attributes.mode.set_mode3_u.mode = fsdev_io->u_in.mknod.mode & 0777;
        args.what.mknoddata3_u.blk_device.spec.specdata1 = major;
        args.what.mknoddata3_u.blk_device.spec.specdata2 = minor;
        break;
    case 0020000:
        args.what.type = NF3CHR; // Character special
        args.what.mknoddata3_u.chr_device.dev_attributes.gid.set_it = 1;
        args.what.mknoddata3_u.chr_device.dev_attributes.gid.set_gid3_u.gid = fsdev_io->u_in.mknod.egid;
        args.what.mknoddata3_u.chr_device.dev_attributes.uid.set_it = 1;
        args.what.mknoddata3_u.chr_device.dev_attributes.uid.set_uid3_u.uid = fsdev_io->u_in.mknod.euid;
        args.what.mknoddata3_u.chr_device.dev_attributes.mode.set_it = 1;
        args.what.mknoddata3_u.chr_device.dev_attributes.mode.set_mode3_u.mode = fsdev_io->u_in.mknod.mode & 0777;
        args.what.mknoddata3_u.chr_device.spec.specdata1 = major;
        args.what.mknoddata3_u.chr_device.spec.specdata2 = minor;
        break;
    case 0140000:
        args.what.type = NF3SOCK; // Socket
        args.what.mknoddata3_u.sock_attributes.gid.set_it = 1;
        args.what.mknoddata3_u.sock_attributes.gid.set_gid3_u.gid = fsdev_io->u_in.mknod.egid;
        args.what.mknoddata3_u.sock_attributes.uid.set_it = 1;
        args.what.mknoddata3_u.sock_attributes.uid.set_uid3_u.uid = fsdev_io->u_in.mknod.euid;
        args.what.mknoddata3_u.sock_attributes.mode.set_it = 1;
        args.what.mknoddata3_u.sock_attributes.mode.set_mode3_u.mode = fsdev_io->u_in.mknod.mode & 0777;
        break;
    case 0010000:
        args.what.type = NF3FIFO; // FIFO
        args.what.mknoddata3_u.pipe_attributes.gid.set_it = 1;
        args.what.mknoddata3_u.pipe_attributes.gid.set_gid3_u.gid = fsdev_io->u_in.mknod.egid;
        args.what.mknoddata3_u.pipe_attributes.uid.set_it = 1;
        args.what.mknoddata3_u.pipe_attributes.uid.set_uid3_u.uid = fsdev_io->u_in.mknod.euid;
        args.what.mknoddata3_u.pipe_attributes.mode.set_it = 1;
        args.what.mknoddata3_u.pipe_attributes.mode.set_mode3_u.mode = fsdev_io->u_in.mknod.mode & 0777;
        break;
    case 0100000:                                                    // regular files
        printf("regular file called mknod instead of create !! \n"); // delete later
        struct CREATE3args args2 = {0};
        args2.where.dir = *my_get(vfsdev->map, (unsigned long)fsdev_io->u_in.mknod.parent_fobject);
        args2.where.name = fsdev_io->u_in.mknod.name;
        args2.how.mode = UNCHECKED; // Or GUARDED, or EXCLUSIVE (UNCHECKED mode creates the file regardless
                                    // of whether it exists. GUARDED fails if the file exists. EXCLUSIVE is for atomic file creation.)
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
    default: // should handle another cases also for dirs and slinks... later...
        // Regular files (NF3REG) are typically created using the CREATE operation.
        // Directories (NF3DIR) are created using the MKDIR operation.
        // Symbolic links (NF3LNK) are created using the SYMLINK operation.

        printf("Unexpected file type in mode: %o\n", fsdev_io->u_in.mknod.mode);
        return -EINVAL;
    }

    if (rpc_nfs3_mknod_task(nfs_get_rpc_context(vch->nfs), lo_mknod_cb, &args, fsdev_io) == NULL)
    {
        printf("ERROR in calling mkdir\n");
        return -EINVAL;
    }
    return OP_STATUS_ASYNC;
}
*/

/*
static void
lo_mknod_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    printf("+=+=+=+=+=+=+=+=  {lo_mknod_cb} FUNCTION CALLED \n");

    struct spdk_fsdev_io *fsdev_io = private_data;
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    if (status == RPC_STATUS_ERROR)
    {
        printf("lo_mknod failed with error [%s]\n", (char *)data);
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("lo_mknod failed \n");
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    struct MKNOD3res *result = data;
    unsigned long new_key = generate_new_key(); // should we check if this symlink already exist ? can it be ?
    my_insert(vfsdev->map, new_key, &result->MKNOD3res_u.resok.obj.post_op_fh3_u.handle);

    fattr3 *res = &result->MKNOD3res_u.resok.obj_attributes.post_op_attr_u.attributes;
    lo_fill_attr(&fsdev_io->u_out.mknod.attr, res, new_key);
    fsdev_io->u_out.mknod.fobject = (struct spdk_fsdev_file_object *)new_key;

    spdk_fsdev_io_complete(fsdev_io, 0);
}
*/

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
    unsigned long new_key = generate_new_key(); // should we check if this symlink already exist ? can it be ?
    my_insert(vfsdev->map, new_key, &result->MKDIR3res_u.resok.obj.post_op_fh3_u.handle);

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
    args.where.dir = *my_get(vfsdev->map, (unsigned long)fsdev_io->u_in.mkdir.parent_fobject);
    args.where.name = fsdev_io->u_in.mkdir.name;
    args.attributes.gid.set_it = 1;
    args.attributes.gid.set_gid3_u.gid = fsdev_io->u_in.mkdir.egid;
    args.attributes.uid.set_it = 1;
    args.attributes.uid.set_uid3_u.uid = fsdev_io->u_in.mkdir.euid;
    args.attributes.mode.set_it = 1;
    args.attributes.mode.set_mode3_u.mode = fsdev_io->u_in.mkdir.mode & 0777; // i am not sure this is the same format !! maybe should add & 0777

    if (rpc_nfs3_mkdir_task(nfs_get_rpc_context(vch->nfs), lo_mkdir_cb, &args, fsdev_io) == NULL)
    {
        printf("ERROR in calling mkdir\n");
        return -EINVAL;
    }
    return OP_STATUS_ASYNC;
}

/*
static void
lo_symlink_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    printf("+=+=+=+=+=+=+=+=  {lo_symlink_cb} FUNCTION CALLED \n");

    struct spdk_fsdev_io *fsdev_io = private_data;
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    if (status == RPC_STATUS_ERROR)
    {
        printf("SYMLINK failed with error [%s]\n", (char *)data);
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("SYMLINK failed \n");
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }

    struct SYMLINK3res *result = data;
    unsigned long new_key = generate_new_key(); // should we check if this symlink already exist ? can it be ?
    my_insert(vfsdev->map, new_key, &result->SYMLINK3res_u.resok.obj.post_op_fh3_u.handle);
    fsdev_io->u_out.symlink.fobject = (struct spdk_fsdev_file_object *)new_key;

    fattr3 *res = &result->SYMLINK3res_u.resok.obj_attributes.post_op_attr_u.attributes;
    lo_fill_attr(&fsdev_io->u_out.symlink.attr, res, new_key);

    spdk_fsdev_io_complete(fsdev_io, 0);
}

static int
lo_symlink(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    printf("+=+=+=+=+=+=+=+=  {lo_symlink} FUNCTION CALLED \n");

    unsigned long parent_inode = (unsigned long)fsdev_io->u_in.symlink.parent_fobject;
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);
    struct SYMLINK3args args = {0};
    struct nfs_fh3 *parent_fh = my_get(vfsdev->map, parent_inode);

    args.where.dir = *parent_fh;
    args.where.name = fsdev_io->u_in.symlink.target;
    args.symlink.symlink_data = fsdev_io->u_in.symlink.linkpath;
    args.symlink.symlink_attributes.gid.set_it = 1;
    args.symlink.symlink_attributes.gid.set_gid3_u.gid = fsdev_io->u_in.symlink.egid;
    args.symlink.symlink_attributes.uid.set_it = 1;
    args.symlink.symlink_attributes.uid.set_uid3_u.uid = fsdev_io->u_in.symlink.euid;

    if (rpc_nfs3_symlink_task(nfs_get_rpc_context(vch->nfs), lo_symlink_cb, &args, fsdev_io) == NULL)
    {
        printf("ERROR in calling symlink\n");
        return -EINVAL;
    }

    return OP_STATUS_ASYNC;
}
*/

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
    [SPDK_FSDEV_OP_LOOKUP] = lo_lookup, //
    [SPDK_FSDEV_OP_FORGET] = nimp,
    [SPDK_FSDEV_OP_GETATTR] = lo_getattr, //
    [SPDK_FSDEV_OP_SETATTR] = nimp,
    [SPDK_FSDEV_OP_READLINK] = nimp,
    [SPDK_FSDEV_OP_SYMLINK] = nimp,   // new1
    [SPDK_FSDEV_OP_MKNOD] = lo_mknod, // new2
    [SPDK_FSDEV_OP_MKDIR] = lo_mkdir, // new3
    [SPDK_FSDEV_OP_UNLINK] = nimp,
    [SPDK_FSDEV_OP_RMDIR] = nimp,
    [SPDK_FSDEV_OP_RENAME] = nimp,
    [SPDK_FSDEV_OP_LINK] = nimp,
    [SPDK_FSDEV_OP_OPEN] = lo_open,   //
    [SPDK_FSDEV_OP_READ] = lo_read,   //
    [SPDK_FSDEV_OP_WRITE] = lo_write, //
    [SPDK_FSDEV_OP_STATFS] = nimp,
    [SPDK_FSDEV_OP_RELEASE] = nimp,
    [SPDK_FSDEV_OP_FSYNC] = nimp,
    [SPDK_FSDEV_OP_SETXATTR] = nimp,
    [SPDK_FSDEV_OP_GETXATTR] = nimp,
    [SPDK_FSDEV_OP_LISTXATTR] = nimp,
    [SPDK_FSDEV_OP_REMOVEXATTR] = nimp,
    [SPDK_FSDEV_OP_FLUSH] = nimp,
    [SPDK_FSDEV_OP_OPENDIR] = lo_opendir, //
    [SPDK_FSDEV_OP_READDIR] = lo_readdir, //
    [SPDK_FSDEV_OP_RELEASEDIR] = nimp,
    [SPDK_FSDEV_OP_FSYNCDIR] = nimp,
    [SPDK_FSDEV_OP_FLOCK] = nimp,
    [SPDK_FSDEV_OP_CREATE] = nimp,
    [SPDK_FSDEV_OP_ABORT] = nimp,
    [SPDK_FSDEV_OP_FALLOCATE] = nimp,
    [SPDK_FSDEV_OP_COPY_FILE_RANGE] = nimp,
};

const char *opNames[] = {
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
    "COPY_FILE_RANGE"};

static void
fsdev_nfs_submit_request(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{

    // printf("fsdev_nfs_submit_request fucntion entered\n"); //
    enum spdk_fsdev_op op = spdk_fsdev_io_get_op(fsdev_io);
    // printf("+=+=+=+=+=+=+=+=  {fsdev_nfs_submit_request} FUNCTION CALLED and we are calling FUNCTION [%s]\n", opNames[op]);
    printf("\033[33m+=+=+=+=+=+=+=+=  {fsdev_nfs_submit_request} FUNCTION CALLED and we are calling FUNCTION [%s]\033[0m\n", opNames[op]);
    assert(op >= 0 && op < __SPDK_FSDEV_OP_LAST);
    // printf("\tZXZXZXZXZX from submit request we are calling function : { %s }\n", opNames[op]); // delete later
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

    // printf("fsdev_nfs_get_io_channel fucntion entered\n"); //
    return spdk_get_io_channel(ctx);
}

static int
fsdev_nfs_negotiate_opts(void *ctx, struct spdk_fsdev_open_opts *opts)
{
    // TO DO ?
    return 0;
}

static void
fsdev_nfs_write_config_json(struct spdk_fsdev *fsdev, struct spdk_json_write_ctx *w)
{
    // TO DO ?
}

static int
fsdev_nfs_reset(void *_ctx, spdk_fsdev_reset_done_cb cb, void *cb_arg)
{
    // TO DO ?
    return 0;
}

static const struct spdk_fsdev_fn_table nfs_fn_table = {
    .destruct = fsdev_nfs_destruct,
    .submit_request = fsdev_nfs_submit_request,
    .get_io_channel = fsdev_nfs_get_io_channel,
    .negotiate_opts = fsdev_nfs_negotiate_opts,
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
        exit(10); // should we exit here ?
    }

    return 1;
}

static int
nfs_io_channel_init_create_cb(void *io_device, void *ctx_buf)
{
    printf("+=+=+=+=+=+=+=+=  {nfs_io_channel_init_create_cb} FUNCTION CALLED \n");

    struct nfs_fsdev *vfsdev = io_device;
    struct nfs_io_channel *vch = ctx_buf;

    // printf("KARAMBA!!!!!\n");
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
    root_fh3.data.data_val = root_fh->val;
    root_fh3.data.data_len = root_fh->len;
    my_insert(vfsdev->map, (unsigned long)1, &root_fh3);

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

    vfsdev->server = "127.0.0.1"; //"10.209.80.42";
    vfsdev->export = "/VIRTUAL";

    vfsdev->map = create_my_map();

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
    // fsdev_nfs_get_io_channel(vfsdev);

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
