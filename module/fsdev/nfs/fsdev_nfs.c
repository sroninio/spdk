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
#include "map2.h"

unsigned long global_key = 17;
///==================== libnfs:

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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <fcntl.h>
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"
#include "libnfs-raw-nfs.h"

//============================== end avi additions

#define OP_STATUS_ASYNC INT_MIN


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

static int
lo_open(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
    fsdev_io->u_out.open.fhandle = (struct spdk_fsdev_file_handle *)fsdev_io->u_in.open.fobject;
	return 0;
}

static void 
lo_write_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{

    struct spdk_fsdev_io *fsdev_io = private_data;
    if (status == RPC_STATUS_ERROR)
    {
        printf("read failed with error [%s]\n", (char*)data);
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
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);

    if(fsdev_io->u_in.write.fhandle != (struct spdk_fsdev_file_handle *)fsdev_io->u_in.write.fobject){
        printf("fh != fobj when should be equal\n");
        return -EINVAL;
    }

    unsigned long inode_key = (unsigned long)fsdev_io->u_in.read.fhandle;
    struct nfs_fh3 *fh = my_get(vfsdev->map, inode_key);

    size_t size = fsdev_io->u_in.write.size;
    uint64_t offs = fsdev_io->u_in.write.offs;
    const struct iovec *invec = fsdev_io->u_in.write.iov;
    uint32_t incnt = fsdev_io->u_in.write.iovcnt;

    if(incnt != 1){
        printf("buffer is splitted\n");
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

static unsigned long 
generate_new_key(void){
    return global_key++;
}

static void 
lo_read_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    struct spdk_fsdev_io *fsdev_io = private_data;
    if (status == RPC_STATUS_ERROR)
    {
        printf("read failed with error [%s]\n", (char*)data);
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("read failed \n");
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }

    fsdev_io->u_out.read.data_size = fsdev_io->u_in.read.size;

    spdk_fsdev_io_complete(fsdev_io, 0);
}

static int
lo_read(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);

    if(fsdev_io->u_in.read.fhandle != (struct spdk_fsdev_file_handle *)fsdev_io->u_in.read.fobject){
        printf("fh != fobj when should be equal\n");
        return -EINVAL;
    }

    unsigned long inode_key = (unsigned long)fsdev_io->u_in.read.fhandle; 
    struct nfs_fh3 *fh = my_get(vfsdev->map, inode_key);

    struct iovec *outvec = fsdev_io->u_in.read.iov;
    uint32_t outcnt = fsdev_io->u_in.read.iovcnt;
    size_t count = fsdev_io->u_in.read.size;
    uint64_t offset = fsdev_io->u_in.read.offs;

    if(outcnt != 1){
        printf("buffer is splitted\n");
        return -EINVAL;
    }

    struct READ3args args = {0};
    args.file = *fh; 
    args.offset = offset;
    args.count = count;

    if (rpc_nfs3_read_task(nfs_get_rpc_context(vch->nfs), lo_read_cb, outvec[0].iov_base, 
                                outvec[0].iov_len, &args, fsdev_io) == NULL){
        printf("error in read request \n");
        return -EINVAL;
    }
    return OP_STATUS_ASYNC;
}

static void 
lo_lookup_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    struct spdk_fsdev_io *fsdev_io = private_data;
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    printf ("KKKKIIIIIINNNNNGGG\n");

    if (status == RPC_STATUS_ERROR)
    {
        printf("LOOKUP failed with error [%s]\n", (char*)data);
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
 
    unsigned long new_key = generate_new_key();

    my_insert(vfsdev->map, new_key, &(result->LOOKUP3res_u.resok.object));

    fsdev_io->u_out.lookup.fobject = (struct spdk_fsdev_file_object *)new_key;

    spdk_fsdev_io_complete(fsdev_io, 0);
}

static int
lo_lookup(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    unsigned long key_parent = (unsigned long)fsdev_io->u_in.lookup.parent_fobject;
    char *name = fsdev_io->u_in.lookup.name;
    printf ("in lookup fuse_inode = %ld, name=%s", key_parent, name);    

    if (key_parent == 0) {
        fsdev_io->u_out.lookup.fobject = (struct spdk_fsdev_file_object *)(1);
        return 0;
    }
    
    struct nfs_fh3 *nfsfh_parent = my_get(vfsdev->map, key_parent); 
    if ( nfsfh_parent->data.data_len == 0) {
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

static void 
lo_getattr_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    struct spdk_fsdev_io *fsdev_io = private_data;

    if (status == RPC_STATUS_ERROR)
    {
        printf("LOOKUP failed with error [%s]\n", (char*)data);
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("LOOKUP failed \n");
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
	struct GETATTR3res * result = data;
	fattr3 * res = &result->GETATTR3res_u.resok.obj_attributes;

	fsdev_io->u_out.getattr.attr.ino = (uint64_t)fsdev_io->u_in.getattr.fhandle;
	fsdev_io->u_out.getattr.attr.size = res->size;
    fsdev_io->u_out.getattr.attr.blocks = 1 ;//
	fsdev_io->u_out.getattr.attr.atime = res->atime.seconds;
	fsdev_io->u_out.getattr.attr.mtime = res->mtime.seconds;
	fsdev_io->u_out.getattr.attr.ctime = res->mtime.seconds;
    fsdev_io->u_out.getattr.attr.atimensec = res->atime.nseconds;
	fsdev_io->u_out.getattr.attr.mtimensec = res->mtime.nseconds;
	fsdev_io->u_out.getattr.attr.ctimensec = res->mtime.nseconds;
	fsdev_io->u_out.getattr.attr.mode = res->mode;    
	fsdev_io->u_out.getattr.attr.nlink = res->nlink;    
	fsdev_io->u_out.getattr.attr.uid = res->uid;
	fsdev_io->u_out.getattr.attr.gid = res->gid;
	fsdev_io->u_out.getattr.attr.rdev = res->rdev.specdata1; //should this be 1 ?    
	fsdev_io->u_out.getattr.attr.blksize =4096;//
	fsdev_io->u_out.getattr.attr.valid_ms = 0;

    spdk_fsdev_io_complete(fsdev_io, 0);
}

static int
lo_getattr(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{

    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    unsigned long key = (unsigned long)fsdev_io->u_in.getattr.fobject;

    printf(" the requesterd key for get attr is %ld \n", key);

	struct GETATTR3args args = {0};
	
    struct nfs_fh3 *nfsfh = my_get(vfsdev->map, key);

	if(nfsfh->data.data_val == 0){
		printf("not in the map \n");
		return -EINVAL;
	}

    args.object = *nfsfh;

    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);

	if(rpc_nfs3_getattr_task(nfs_get_rpc_context(vch->nfs), lo_getattr_cb, &args, fsdev_io) ==NULL){
		printf("error in getting attributes \n");
		return -EINVAL;
	}

    return OP_STATUS_ASYNC;
}

static int 
lo_opendir(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io){
    fsdev_io->u_out.open.fhandle = (struct spdk_fsdev_file_handle *)fsdev_io->u_in.open.fobject;
	return 0;
}


static void
lo_readdir_cb(struct rpc_context *rpc, int status, void *data, void *private_data){
    struct spdk_fsdev_io *fsdev_io = private_data;
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    if (status == RPC_STATUS_ERROR)
    {
        printf("READDIR failed with error [%s]\n", (char*)data);
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }
    else if (status == RPC_STATUS_CANCEL)
    {
        printf("READDIR failed \n");
        spdk_fsdev_io_complete(fsdev_io, -EINVAL);
        return;
    }

    struct READDIRPLUS3res * res = data;
    dirlistplus3 list_head = res->READDIRPLUS3res_u.resok.reply;
    entryplus3* curr_entry = list_head.entries;
    int counter = 0;
    int rc = 0;
    while(curr_entry!=NULL){
        my_insert(vfsdev->map, generate_new_key(), &(curr_entry->name_handle.post_op_fh3_u.handle));
        
        fsdev_io->u_out.readdir.name = curr_entry->name;
        fsdev_io->u_out.readdir.offset = curr_entry->cookie;
        rc = fsdev_io->u_in.readdir.entry_cb_fn(fsdev_io, fsdev_io->internal.cb_arg);
        curr_entry = curr_entry->nextentry;
    }

    spdk_fsdev_io_complete(fsdev_io, rc);
}

static int
lo_readdir(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io){
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);

    if(fsdev_io->u_in.readdir.fhandle != (struct spdk_fsdev_file_handle *)fsdev_io->u_in.readdir.fobject){
        printf("Failed in readdir because fh != fobj when should be equal\n");
        return -EINVAL;
    }

    unsigned long key = (unsigned long)fsdev_io->u_in.readdir.fobject;
    struct nfs_fh3 *nfsfh = my_get(vfsdev->map, key);

    
    /* we are only supporting READDIRPLUS */
    //if(fsdev_io->u_in.readdir != readdir_plus){
    //  printf("we are only supporting readdir plus \n");
    //  return -EINVAL;
    //} 
    
    uint64_t offset = fsdev_io->u_in.readdir.offset;
    if(offset != 0){
        printf("Failed - big directories are not supported\n");
        return -EINVAL;
    }

    struct READDIRPLUS3args args;
    args.dir = *nfsfh;
    args.cookie = offset;
    // args.cookieverf = NULL;
    args.dircount = 1000000;
    args.maxcount = 1000000;

    if(rpc_nfs3_readdirplus_task(nfs_get_rpc_context(vch->nfs), lo_readdir_cb, &args, fsdev_io)==NULL){
        printf("ERROR in calling readdir\n");
        return -EINVAL;
    }

    return OP_STATUS_ASYNC;
}



static int
fsdev_nfs_initialize(void)
{
    printf("fsdev_nfs_initialize fucntion entered\n");
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
	return -ENOSYS;
}

static fsdev_op_handler_func handlers[] = {
    [SPDK_FSDEV_OP_LOOKUP] = lo_lookup,
    [SPDK_FSDEV_OP_FORGET] = nimp,
    [SPDK_FSDEV_OP_GETATTR] = lo_getattr,
    [SPDK_FSDEV_OP_SETATTR] = nimp,
    [SPDK_FSDEV_OP_READLINK] = nimp,
    [SPDK_FSDEV_OP_SYMLINK] = nimp,
    [SPDK_FSDEV_OP_MKNOD] = nimp,
    [SPDK_FSDEV_OP_MKDIR] = nimp,
    [SPDK_FSDEV_OP_UNLINK] = nimp,
    [SPDK_FSDEV_OP_RMDIR] = nimp,
    [SPDK_FSDEV_OP_RENAME] = nimp,
    [SPDK_FSDEV_OP_LINK] = nimp,
    [SPDK_FSDEV_OP_OPEN] = lo_open,
    [SPDK_FSDEV_OP_READ] = lo_read,
    [SPDK_FSDEV_OP_WRITE] = lo_write,
    [SPDK_FSDEV_OP_STATFS] =  nimp,
    [SPDK_FSDEV_OP_RELEASE] = nimp,
    [SPDK_FSDEV_OP_FSYNC] = nimp,
    [SPDK_FSDEV_OP_SETXATTR] = nimp,
    [SPDK_FSDEV_OP_GETXATTR] = nimp,
    [SPDK_FSDEV_OP_LISTXATTR] = nimp,
    [SPDK_FSDEV_OP_REMOVEXATTR] =  nimp,
    [SPDK_FSDEV_OP_FLUSH] =  nimp,
    [SPDK_FSDEV_OP_OPENDIR] =  lo_opendir,
    [SPDK_FSDEV_OP_READDIR] =  lo_read,
    [SPDK_FSDEV_OP_RELEASEDIR] = nimp,
    [SPDK_FSDEV_OP_FSYNCDIR] = nimp,
    [SPDK_FSDEV_OP_FLOCK] = nimp,
    [SPDK_FSDEV_OP_CREATE] = nimp,
    [SPDK_FSDEV_OP_ABORT] = nimp,
    [SPDK_FSDEV_OP_FALLOCATE] = nimp,
    [SPDK_FSDEV_OP_COPY_FILE_RANGE] = nimp,
};

const char* opNames[] = {
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
    "COPY_FILE_RANGE"
};

static void
fsdev_nfs_submit_request(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
    printf("fsdev_nfs_submit_request fucntion entered\n");
    enum spdk_fsdev_op op = spdk_fsdev_io_get_op(fsdev_io);

    assert(op >= 0 && op < __SPDK_FSDEV_OP_LAST);
    printf("\tZXZXZXZXZX from submit request we are calling function : { %s }\n", opNames[op]);//delete later
    int status = handlers[op](ch, fsdev_io);
    if (status != OP_STATUS_ASYNC)
    {
        spdk_fsdev_io_complete(fsdev_io, status);
    }
}

static struct spdk_io_channel *
fsdev_nfs_get_io_channel(void *ctx)
{
    printf("fsdev_nfs_get_io_channel fucntion entered\n");
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

    struct nfs_fsdev *vfsdev = io_device;
    struct nfs_io_channel *vch = ctx_buf; 

   
    printf("KARAMBA!!!!!\n");
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
    const struct nfs_fh * root_fh = nfs_get_rootfh(vch->nfs);
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
    printf("spdk_fsdev_nfs_create fucntion entered\n");
    struct nfs_fsdev *vfsdev;
    vfsdev = calloc(1, sizeof(*vfsdev));
    if (!vfsdev)
    {
        SPDK_ERRLOG("Could not allocate nfs fsdev\n");
        return -ENOMEM;
    }

    vfsdev->server = "10.209.80.42";
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
