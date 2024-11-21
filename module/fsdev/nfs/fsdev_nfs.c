/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */
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
#include "c_to_cpp_pipe.h"
#include "fuse_kernel.h"


#define BITS_MASK 0170000
#define REGULAR_FILE 0100000


bool global_test = true; // delete later
bool second_test2 = true;
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


#define OPEN_CLOSE_STRUCT_REPLY_MAGIC_NUM 0x2244387115
#define INIT_VALUE_XID 0

static void compiler_barrier(void)
{
    __asm volatile("" ::: "memory");
}

struct OpenCloseReply
{
    unsigned long header_xid;
    unsigned long expected_ref_count;
    unsigned long file_inode;
    unsigned long magic_number;
    unsigned long suffix_xid;
};


struct nfs_fsdev
{
    char *server;
    char *export;
    void *db;
    struct OpenCloseReply *open_close_reply_struct;   
    struct nfs_context *nfs;
    struct pollfd pfds[2]; /* nfs:0  mount:1 */    
};

struct async_context 
{
    struct nfs_fsdev *fsdev; 
    char *fuse_header;
    char *fuse_in;
    char *fuse_out;
    APP_CB app_cb;
    void * app_ctx;
};


static void
complete(struct async_context * context, size_t len, int status);

static void
lo_initilize_open_close_reply_struct(struct OpenCloseReply *open_close_reply_struct);

static void
lo_restore_open_close_reply_struct(struct OpenCloseReply *open_close_reply_struct, int fd, struct nfs_fsdev *vfsdev);

static struct OpenCloseReply *
lo_allocate_and_init_open_close_reply_struct(char *filename, struct nfs_fsdev *vfsdev);


static struct async_context * 
alloc_init_async_context(struct nfs_fsdev *fsdev, char *fuse_header, 
    char *fuse_in, char * fuse_out, APP_CB cb, void * ctx)
{
    struct async_context * res = calloc(1, sizeof(*res));
    res->fsdev = fsdev;
    res->fuse_header = fuse_header;
    res->fuse_in = fuse_in;
    res->fuse_out = fuse_out;
    res->app_cb = cb;
    res->app_ctx = ctx;
    return res;
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
    return insert_entry(db, &temp, temp.inode_left_key, &temp.fh_right_key);
}

static bool
lo_initialize_new_root_entry_and_insert_to_db(unsigned long inode, const struct nfs_fh *fh, struct nfs_fsdev *fsdev)
{
    struct NfsFsdevEntry temp_entry = {0};
    temp_entry.inode_left_key = inode;
    temp_entry.ref_count = 0;
    temp_entry.fh_right_key.data.data_len = fh->len;
    memcpy(temp_entry.fh_right_key.data.data_val, fh->val, fh->len);
    temp_entry.state = REGULAR_STATE;
    return insert_entry(fsdev->db, &temp_entry, inode, &temp_entry.fh_right_key);
}

static uint32_t 
get_rdev(fattr3 * res)
{
    if (S_ISCHR(res->mode) || S_ISBLK(res->mode))
    {
        return makedev(res->rdev.specdata1, res->rdev.specdata2);
    }
    else
    {
        return 0;
    }

}

static uint32_t 
get_mode(fattr3 * res)
{
    uint32_t mode = 0;
    switch (res->type)
    {
    case NF3REG:
        mode = 0100000 + res->mode; // Regular file
        break;
    case NF3DIR:
        mode = 0040000 + res->mode; // Directory
        break;
    case NF3BLK:
        mode = 0060000 + res->mode; // Block special
        break;
    case NF3CHR:
        mode = 0020000 + res->mode; // Character special
        break;
    case NF3LNK:
        mode = 0120000 + res->mode; // Symbolic link
        break;
    case NF3SOCK:
        mode = 0140000 + res->mode; // Socket
        break;
    case NF3FIFO:
        mode = 0010000 + res->mode; // FIFO
        break;
    default:
        // Handle unexpected file type as Regular file
        mode = 0100000 + res->mode;
	exit(1);
        break;
    }
    return mode;
}

static void
lo_fill_roman_1(struct fuse_entry_out *arg, fattr3 *res)
{
	arg->attr_valid = 0;
	arg->attr_valid_nsec = 0; 
}

static void
lo_fill_entry(struct fuse_entry_out *arg, fattr3 *res, int inode)
{
	arg->nodeid = inode;
	arg->generation = 0;
	arg->entry_valid = 0; 
	arg->entry_valid_nsec = 0; 
	arg->attr_valid = 0;
	arg->attr_valid_nsec = 0; 
}

static void
lo_fill_attr(struct fuse_entry_out *arg, fattr3 *res, int ino)
{
	arg->attr.ino	= ino;
	arg->attr.mode	= get_mode(res);
	arg->attr.nlink = res->nlink;
	arg->attr.uid	= res->uid;
	arg->attr.gid	= res->gid;
	arg->attr.rdev	= get_rdev(res);
	arg->attr.size = res->size;
	arg->attr.blksize = 4096;
	arg->attr.blocks = (res->size + 511) / 512;
	arg->attr.atime	= res->atime.seconds;
	arg->attr.mtime	= res->mtime.seconds;
	arg->attr.ctime	= res->ctime.seconds;
	arg->attr.atimensec = res->atime.nseconds;
	arg->attr.mtimensec = res->mtime.nseconds;
	arg->attr.ctimensec = res->ctime.nseconds;
}



static void
lo_getattr_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    struct async_context * ctx = private_data;


    struct fuse_in_header * hdr = (struct fuse_in_header *)(ctx->fuse_header);
    struct fuse_out_header * out_header = (struct fuse_out_header * )(ctx->fuse_out);
    struct fuse_entry_out * outarg = (struct fuse_entry_out *)(out_header + 1);


    printf("+=+=+=+=+=+=+=+=  {lo_getattr_cb} FUNCTION CALLED \n");
    fflush(stdout);


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

    lo_fill_attr(outarg, res, hdr->nodeid);
    lo_fill_roman_1(outarg, res);
    complete(ctx, sizeof(*outarg), 0);
}

static struct GETATTR3args
lo_getattr_args(struct NfsFsdevEntry *entry)
{
    struct GETATTR3args args = {0};
    args.object.data.data_len = entry->fh_right_key.data.data_len;
    args.object.data.data_val = entry->fh_right_key.data.data_val;
    return args;
}

static void
lo_getattr(struct async_context * context)
{
    struct fuse_in_header * hdr = (struct fuse_in_header *)(context->fuse_header);
    printf("+=+=+=+=+=+=+=+=  {lo_getattr} FUNCTION CALLED with inode number [%ld] \n", hdr->nodeid);


    if (check_if_exist_by_left(context->fsdev->db, hdr->nodeid) == false)
    {
        printf("Error: trying to get attributes of none exisiting entry\n");
        exit(1);
    }

    struct NfsFsdevEntry temp = get_entry_by_left(context->fsdev->db, hdr->nodeid);
    if (temp.state == PENDING_DELETION_STATE)
    {
        printf("Warnning: Trying to make I/O request on inode that is pending deletion\n");
        exit(1);
    }

    struct GETATTR3args args = lo_getattr_args(&temp);


    if (rpc_nfs3_getattr_task(nfs_get_rpc_context(context->fsdev->nfs), lo_getattr_cb, &args, context) == NULL)
    {
        printf("Error: in getting attributes \n");
        exit(1);
    }
}

static void
lo_init(struct async_context * context)
{
    struct fuse_out_header * out_header = (struct fuse_out_header * )(context->fuse_out);
    struct fuse_init_out * outarg = (struct fuse_init_out *)(out_header + 1);

	outarg->major = 7;
	outarg->minor = 34;
	outarg->max_readahead = 131072;
	outarg->flags = 1004469371;
	outarg->max_background = 65535; //RSRS
    	outarg->congestion_threshold = 65535; //RSRS
	outarg->max_write = 131072;
	outarg->time_gran = 1;
	outarg->max_pages = 32;
	outarg->map_alignment = 0;
	memset(outarg->unused, 0, sizeof(outarg->unused));
    complete(context, sizeof(*outarg), 0);
}


static void
lo_lookup_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    printf("+=+=+=+=+=+=+=+=  {lo_lookup_cb} FUNCTION CALLED \n");

    struct async_context * ctx = private_data;

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
            exit(1);
        }
        else
        {
            printf("Error: lookup result is other than OK or NOENT = [%d]\n", ret);
            exit(1);
        }
        return;
    }

    struct persistent_nfs_fh3 temp_fh = {0};
    temp_fh.data.data_len = result->LOOKUP3res_u.resok.object.data.data_len;
    memcpy(temp_fh.data.data_val, result->LOOKUP3res_u.resok.object.data.data_val, temp_fh.data.data_len);
    unsigned long inode;

    if (check_if_exist_by_right(ctx->fsdev->db, &temp_fh))
    {
        struct NfsFsdevEntry temp = get_entry_by_right(ctx->fsdev->db, &temp_fh);
        if (temp.state == PENDING_DELETION_STATE)
        {
            printf("Error: Trying to make I/O request on a file that is pending deletion\n");
            exit(1);
        }
        inode = temp.inode_left_key;
    }
    else
    {
        inode = generate_left_key(ctx->fsdev->db);
        if (!lo_insert_to_data_base(ctx->fsdev->db, REGULAR_STATE, 0, inode, &result->LOOKUP3res_u.resok.object))
        {
            printf("Error:  falied at inserting new entry to our data base \n");
            exit(1);
        }
    }
    printf("$$$$$$ WE ARE RETURNNING INODE %ld\n", inode); //
    fattr3 *res = &result->LOOKUP3res_u.resok.obj_attributes.post_op_attr_u.attributes;
    lo_fill_entry((struct fuse_entry_out *)(ctx->fuse_out), res, inode);
    lo_fill_attr((struct fuse_entry_out *)(ctx->fuse_out), res, inode);
    complete(ctx, sizeof(struct fuse_entry_out), 0);
}


static void
lo_lookup(struct async_context * context)
{
    struct fuse_in_header * hdr = (struct fuse_in_header *)(context->fuse_header);
    char * name = strdup(context->fuse_in);

    printf("+=+=+=+=+=+=+=+=  {lo_lookup} FUNCTION CALLED fuse_inode = %ld, name=%s\n", hdr->nodeid, name);
    fflush(stdout);

    if (hdr->nodeid == 0)
    {
        printf("\033[1;31mError: WE ARE CALLING LOOK UP WITH PARENT INODE = 0 !!\033[0m\n");
        exit(1);
    }

    if (check_if_exist_by_left(context->fsdev->db, hdr->nodeid) == false)
    {
        printf("Error: parent directory none known - can lookup child\n");
        exit(1);
    }

    struct NfsFsdevEntry temp = get_entry_by_left(context->fsdev->db, hdr->nodeid);
    if (temp.state == PENDING_DELETION_STATE)
    {
        printf("Warning: Trying to make I/O request on a file with parent directory that is pending deletion\n");
        exit(1);
    }

    struct LOOKUP3args args = {0};
    args.what.dir.data.data_len = temp.fh_right_key.data.data_len;
    args.what.dir.data.data_val = temp.fh_right_key.data.data_val;
    args.what.name = name;

    if (rpc_nfs3_lookup_task(nfs_get_rpc_context(context->fsdev->nfs), lo_lookup_cb, &args, context) == NULL)
    {
        printf("Error: in calling lookup\n");
        exit(1);
    }
}


static void
lo_readdir_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    printf("+=+=+=+=+=+=+=+=  {lo_readdir_cb} FUNCTION CALLED \n");

    struct async_context * ctx = private_data;

    struct fuse_out_header *hdr_out = (struct fuse_out_header * )ctx->fuse_out;
    struct fuse_dirent *dirent = (struct fuse_dirent *)(hdr_out + 1);
    size_t total_len = 0;


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

        unsigned long inode = 0;

        if (curr_entry->name_handle.post_op_fh3_u.handle.data.data_len == 0)
        {
            curr_entry = curr_entry->nextentry;
            continue;
        }

        if (check_if_exist_by_right(ctx->fsdev->db, &temp_fh))
        {
            struct NfsFsdevEntry temp = get_entry_by_right(ctx->fsdev->db, &temp_fh);
            if (temp.state == PENDING_DELETION_STATE)
            {
                curr_entry = curr_entry->nextentry;
                continue;
            }

            inode = temp.inode_left_key;
        }
        else
        {
            inode = generate_left_key(ctx->fsdev->db);
            if (!lo_insert_to_data_base(ctx->fsdev->db, REGULAR_STATE, 0, inode, &curr_entry->name_handle.post_op_fh3_u.handle))
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
        size_t namelen;
        size_t entlen;
        size_t entlen_padded;
        namelen = strlen(curr_entry->name);
        entlen = FUSE_NAME_OFFSET + namelen;
        entlen_padded = FUSE_DIRENT_ALIGN(entlen);
        dirent->ino = inode;
        dirent->off = curr_entry->cookie;
        dirent->namelen = namelen;
        dirent->type = (get_mode(&curr_entry->name_attributes.post_op_attr_u.attributes) & 0170000) >> 12;
        memcpy(dirent->name, curr_entry->name, namelen);
        memset(dirent->name + namelen, 0, entlen_padded - entlen);
        curr_entry = curr_entry->nextentry;
        dirent = (struct fuse_dirent *)(((char*)dirent) + entlen_padded);
        total_len += entlen_padded;
    }
    complete(ctx, total_len, 0);
}

static struct READDIRPLUS3args
lo_readdir_args(size_t offset, struct NfsFsdevEntry *entry)
{
    struct READDIRPLUS3args args = {0};
    args.dir.data.data_len = entry->fh_right_key.data.data_len;
    args.dir.data.data_val = entry->fh_right_key.data.data_val;
    args.cookie = offset;
    args.dircount = 1000000;
    args.maxcount = 1000000;
    return args;
}

static void
lo_readdir(struct async_context * context)
{
    struct fuse_in_header * hdr = (struct fuse_in_header *)(context->fuse_header);
    struct fuse_read_in * read_in = (struct fuse_read_in *)(context->fuse_in);

    printf("+=+=+=+=+=+=+=+=  {lo_readdir} FUNCTION CALLED for inode number [%ld]\n", hdr->nodeid);

    if (check_if_exist_by_left(context->fsdev->db, hdr->nodeid) == false)
    {
        printf("Error: none existing directory - can't read this directory\n");
        exit(1);
    }

    struct NfsFsdevEntry temp = get_entry_by_left(context->fsdev->db, hdr->nodeid);
    if (temp.state == PENDING_DELETION_STATE)
    {
        printf("Error: Trying to make I/O request on inode that is pending deletion\n");
        exit(1);
    }

    struct READDIRPLUS3args args = lo_readdir_args(read_in->offset, &temp);

    if (rpc_nfs3_readdirplus_task(nfs_get_rpc_context(context->fsdev->nfs), lo_readdir_cb, &args, context) == NULL)
    {
        printf("Error: in calling readdir\n");
        exit(1);
    }
}


static void
lo_mknod_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
    printf("+=+=+=+=+=+=+=+=  {lo_mknod_cb} FUNCTION CALLED \n");
    struct async_context * ctx = private_data;

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

    if (result->CREATE3res_u.resok.obj.post_op_fh3_u.handle.data.data_len > MAX_FH_DATA_LEN)
    {
        printf("Error: file handle returned in mknod too long\n");
        exit(1);
    }

    struct persistent_nfs_fh3 temp_fh = {0};
    temp_fh.data.data_len = result->CREATE3res_u.resok.obj.post_op_fh3_u.handle.data.data_len;
    memcpy(temp_fh.data.data_val, result->CREATE3res_u.resok.obj.post_op_fh3_u.handle.data.data_val, temp_fh.data.data_len);

    if (check_if_exist_by_right(ctx->fsdev->db, &temp_fh))
    {
        struct NfsFsdevEntry real_entry = get_entry_by_right(ctx->fsdev->db, &temp_fh);

        if (real_entry.state == PENDING_DELETION_STATE)
        {
            printf("Error: edge case - NFS target reused this file handle ! \n");
            exit(1);
        }
        else
        {
            printf("Warning: reply of mknod\n");
            fattr3 *res = &result->CREATE3res_u.resok.obj_attributes.post_op_attr_u.attributes;
            lo_fill_entry((struct fuse_entry_out *)(ctx->fuse_out), res, real_entry.inode_left_key);
            lo_fill_attr((struct fuse_entry_out *)(ctx->fuse_out), res, real_entry.inode_left_key);
            goto COMPLETE;
        }
    }

    unsigned long new_inode = generate_left_key(ctx->fsdev->db);

    if (!lo_insert_to_data_base(ctx->fsdev->db, REGULAR_STATE, 0, new_inode, &result->CREATE3res_u.resok.obj.post_op_fh3_u.handle))
    {
        printf("Error: falied at inserting new entry to our data base \n");
        exit(1);
    }

    fattr3 *res = &result->CREATE3res_u.resok.obj_attributes.post_op_attr_u.attributes;

    lo_fill_entry((struct fuse_entry_out *)(ctx->fuse_out), res, new_inode);
    lo_fill_attr((struct fuse_entry_out *)(ctx->fuse_out), res, new_inode);

COMPLETE:
    complete(ctx, sizeof(struct fuse_entry_out), 0);
}

static struct CREATE3args
lo_mknod_args(struct fuse_in_header * hdr_in ,struct fuse_mknod_in *mknod_in, char * name,  struct NfsFsdevEntry *entry)
{
    struct CREATE3args args = {0};
    args.where.dir.data.data_len = entry->fh_right_key.data.data_len;
    args.where.dir.data.data_val = entry->fh_right_key.data.data_val;
    args.where.name = strdup(name); //RSRS better safe than sorry
    args.how.mode = UNCHECKED; // Or GUARDED, or EXCLUSIVE (UNCHECKED mode creates the file regardless of whether it exists. GUARDED fails if the file exists. EXCLUSIVE is for atomic file creation.)
    args.how.createhow3_u.obj_attributes.mode.set_it = 1;
    args.how.createhow3_u.obj_attributes.mode.set_mode3_u.mode = mknod_in->mode & 0777;
    args.how.createhow3_u.obj_attributes.uid.set_it = 1;
    args.how.createhow3_u.obj_attributes.uid.set_uid3_u.uid = hdr_in->uid;
    args.how.createhow3_u.obj_attributes.gid.set_it = 1;
    args.how.createhow3_u.obj_attributes.gid.set_gid3_u.gid = hdr_in->gid;
    return args;
}


static void 
lo_mknod(struct async_context * context)
{
    printf("+=+=+=+=+=+=+=+=  {lo_mknod} FUNCTION CALLED \n");
    struct fuse_in_header * hdr = (struct fuse_in_header *)(context->fuse_header);
    struct fuse_mknod_in *mknod_in = (struct fuse_mknod_in *)(context->fuse_in);
    char * name = (char *)(mknod_in + 1);

    switch (mknod_in->mode & BITS_MASK)
    {
    case REGULAR_FILE:
        if (check_if_exist_by_left(context->fsdev->db, hdr->nodeid) == false)
        {
            printf("Error: trying to create a new file in a directory that is pending deletion\n");
            exit(1);
        }

        struct NfsFsdevEntry temp = get_entry_by_left(context->fsdev->db, hdr->nodeid);
        assert(temp.state != PENDING_DELETION_STATE);
        struct CREATE3args args = lo_mknod_args(hdr, mknod_in, name, &temp); 

        if (rpc_nfs3_create_task(nfs_get_rpc_context(context->fsdev->nfs), lo_mknod_cb, &args, context) == NULL)
        {
            printf("Error: in calling create\n");
            exit(1);
        }
        break;
    default:
        printf("Error: Unexpected file type(HARD LINKS, SOFT LINKS, ETC) in mode: %o\n", mknod_in->mode);
        exit(1);
    }
}

static void
lo_update_open_close_reply_struct(unsigned long xid, unsigned long inode, unsigned long expected_ref_count, struct OpenCloseReply *ptr)
{
    ptr->header_xid = xid;
    compiler_barrier();

    ptr->file_inode = inode;
    ptr->expected_ref_count = expected_ref_count;

    compiler_barrier();
    ptr->suffix_xid = xid;
}

static void
lo_open(struct async_context * context)
{
    struct fuse_in_header * hdr = (struct fuse_in_header *)(context->fuse_header);
    struct fuse_open_out *open_out = (struct fuse_open_out *)(context->fuse_out);

    unsigned long xid = hdr->unique;
    printf("the xid of the current open request is %ld \n", xid);                           //
    printf("the inode of the current open request is %ld \n", hdr->nodeid); //
    fflush(stdout);

    if (xid <= context->fsdev->open_close_reply_struct->suffix_xid) // should it be equel !? I think so.
    {
        printf("Warning: got and old I/O request\n");
        printf("the xid of the crashed X.struct IO request is %ld", context->fsdev->open_close_reply_struct->suffix_xid); //
        open_out->fh = hdr->nodeid;

        goto COMPLETE;

    }

    if (check_if_exist_by_left(context->fsdev->db, hdr->nodeid) == false)
    {
        printf("Error: trying to open a unknown file\n");
        exit(1);
    }

    struct NfsFsdevEntry temp = get_entry_by_left(context->fsdev->db, hdr->nodeid);

    if (temp.state == PENDING_DELETION_STATE)
    {
        printf("Error: trying to get new file descriptor for a file that is pending deletion\n");
        exit(1);
    }

    temp.ref_count++;

    lo_update_open_close_reply_struct(xid, hdr->nodeid, temp.ref_count, context->fsdev->open_close_reply_struct);
    compiler_barrier();

    if (!update_entry_by_left(context->fsdev->db, &temp, temp.inode_left_key))
    {
        printf("Error: falied at open I/O request - updating the data base \n");
        exit(1);
    }
    open_out->fh = hdr->nodeid;

COMPLETE:
    complete(context, sizeof(*open_out), 0);
}



static void
lo_release(struct async_context * context)
{
    struct fuse_in_header * hdr = (struct fuse_in_header *)(context->fuse_header);
    struct fuse_release_in *release_in = (struct fuse_release_in *)(context->fuse_in);

    unsigned long xid = hdr->unique;

    printf("the xid of the current release request is %ld \n", xid);                              //
    printf("the inode of the current release request is %ld \n", release_in->fh); //
    fflush(stdout);

    if (xid <= context->fsdev->open_close_reply_struct->suffix_xid)
    {
        printf("Warning: got and old I/O request\n");
        goto COMPLETE;
    }

    if (check_if_exist_by_left(context->fsdev->db, hdr->nodeid) == false)
    {
        printf("Error: trying to close fd that don't have an entry in data base \n");
        exit(1);
    }

    struct NfsFsdevEntry temp = get_entry_by_left(context->fsdev->db, hdr->nodeid);
    temp.ref_count--;

    lo_update_open_close_reply_struct(xid, hdr->nodeid, temp.ref_count, context->fsdev->open_close_reply_struct);

    compiler_barrier();

    if (temp.ref_count == 0 && temp.state == PENDING_DELETION_STATE)
    {
        printf("NO SEPA POSSIB\n");
        exit(1);
        /* RSRS NOT NOW
        printf("WE ARE HERE ?????!!!!\n");
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
        */
    }

    if (!update_entry_by_left(context->fsdev->db, &temp, temp.inode_left_key))
    {
        printf("Error: falied at release I/O request - updating the data base \n");
        exit(1);
    }
COMPLETE:
    complete(context, 0, 0);
}

static void
lo_write(struct async_context * context)
{
    struct fuse_write_in  *write_in = (struct fuse_write_in *)(context->fuse_in);
    struct fuse_out_header * out_header = (struct fuse_out_header * )(ctx->fuse_out);
    struct fuse_write_out  *write_out = (struct fuse_write_out *)(out_header + 1);

    write_out->size = write_in->size;
    complete(conetxt, sizeof(*write_out) ,0)
}


static void
lo_read(struct async_context * context)
{
    printf("+=+=+=+=+=+=+=+=  {lo_read} FUNCTION CALLED \n");
    struct fuse_read_in  *read_in = (struct fuse_read_in *)(context->fuse_in);
    complete(context, read_in->size, 0);

/* RSRS NOT NOW
    struct nfs_fsdev *vfsdev = fsdev_to_nfs_fsdev(fsdev_io->fsdev);
    struct nfs_io_channel *vch = (struct nfs_io_channel *)spdk_io_channel_get_ctx(_ch);
    struct iovec *outvec = fsdev_io->u_in.read.iov;

    printf("the file indoe we need to read is %ld\n", (unsigned long)fsdev_io->u_in.read.fhandle);

    if (check_if_exist_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.read.fhandle) == false)
    {
        printf("Error: trying to read a none existing file\n");
        exit(1);
    }

    struct NfsFsdevEntry temp = get_entry_by_left(vfsdev->db, (unsigned long)fsdev_io->u_in.read.fhandle);
    if (temp.state == PENDING_DELETION_STATE)
    {
        printf("Warning: Trying to make I/O request on inode that is pending deletion\n");
        if (temp.ref_count == 0)
        {
            return -EINVAL;
        }
    }

    struct READ3args args = lo_read_args(fsdev_io, &temp);

    if (rpc_nfs3_read_task(nfs_get_rpc_context(vch->nfs), lo_read_cb, outvec[0].iov_base,
                           outvec[0].iov_len, &args, fsdev_io) == NULL)
    {
        printf("Error: in read request \n");
        exit(1);
    }
    return OP_STATUS_ASYNC;
*/
}


static void
nimp(struct async_context * context)
{
    printf("+=+=+=+=+=+=+=+=  {nimp} FUNCTION CALLED \n");
    complete(context, 0, -ENOSYS);
}



static const struct {
	void (*func)(struct async_context * context);
	const char *name;
} fuse_ll_ops[] = {
	[FUSE_LOOKUP]	   = { lo_lookup,      "LOOKUP"	     },
	[FUSE_FORGET]	   = { nimp,      "FORGET"	     },
	[FUSE_GETATTR]	   = { lo_getattr,     "GETATTR"     },
	[FUSE_SETATTR]	   = { nimp,     "SETATTR"     },
	[FUSE_READLINK]	   = { nimp,    "READLINK"    },
	[FUSE_SYMLINK]	   = { nimp,     "SYMLINK"     },
	[FUSE_MKNOD]	   = { lo_mknod,       "MKNOD"	     },
	[FUSE_MKDIR]	   = { nimp,       "MKDIR"	     },
	[FUSE_UNLINK]	   = { nimp,      "UNLINK"	     },
	[FUSE_RMDIR]	   = { nimp,       "RMDIR"	     },
	[FUSE_RENAME]	   = { nimp,      "RENAME"	     },
	[FUSE_LINK]	   = { nimp,	       "LINK"	     },
	[FUSE_OPEN]	   = { lo_open,	       "OPEN"	     },
	[FUSE_READ]	   = { lo_read,       "READ"	     },
	[FUSE_WRITE]	   = { lo_write,       "WRITE"	     },
	[FUSE_STATFS]	   = { nimp,      "STATFS"	     },
	[FUSE_RELEASE]	   = { lo_release,     "RELEASE"     },
	[FUSE_FSYNC]	   = { nimp,       "FSYNC"	     },
	[FUSE_SETXATTR]	   = { nimp,    "SETXATTR"    },
	[FUSE_GETXATTR]	   = { nimp,    "GETXATTR"    },
	[FUSE_LISTXATTR]   = { nimp,   "LISTXATTR"   },
	[FUSE_REMOVEXATTR] = { nimp, "REMOVEXATTR" },
	[FUSE_FLUSH]	   = { nimp,       "FLUSH"	     },
	[FUSE_INIT]	   = { lo_init,	       "INIT"	     },
	[FUSE_OPENDIR]	   = { nimp,     "OPENDIR"     },
	[FUSE_READDIR]	   = { lo_readdir,     "READDIR"     },
	[FUSE_RELEASEDIR]  = { nimp,  "RELEASEDIR"  },
	[FUSE_FSYNCDIR]	   = { nimp,    "FSYNCDIR"    },
	[FUSE_GETLK]	   = { nimp,       "GETLK"	     },
	[FUSE_SETLK]	   = { nimp,       "SETLK"	     },
	[FUSE_SETLKW]	   = { nimp,      "SETLKW"	     },
	[FUSE_ACCESS]	   = { nimp,      "ACCESS"	     },
	[FUSE_CREATE]	   = { nimp,      "CREATE"	     },
	[FUSE_INTERRUPT]   = { nimp,   "INTERRUPT"   },
	[FUSE_BMAP]	   = { nimp,	       "BMAP"	     },
	[FUSE_IOCTL]	   = { nimp,       "IOCTL"	     },
	[FUSE_POLL]	   = { nimp,        "POLL"	     },
	[FUSE_FALLOCATE]   = { nimp,   "FALLOCATE"   },
	[FUSE_DESTROY]	   = { nimp,     "DESTROY"     },
	[FUSE_NOTIFY_REPLY] = { NULL,    "NOTIFY_REPLY" },
	[FUSE_BATCH_FORGET] = { nimp, "BATCH_FORGET" },
	[FUSE_READDIRPLUS] = { nimp,	"READDIRPLUS"},
	[FUSE_RENAME2]     = { nimp,      "RENAME2"    },
	[FUSE_COPY_FILE_RANGE] = { nimp, "COPY_FILE_RANGE" },
	[FUSE_SETUPMAPPING]  = { nimp, "SETUPMAPPING" },
	[FUSE_REMOVEMAPPING] = { nimp, "REMOVEMAPPING" },
	[FUSE_SYNCFS] = {nimp , "SYNCFS" },
	[FUSE_LSEEK] = { nimp, "LSEEK" },
};


void
submit(struct nfs_fsdev *fsdev, char * fuse_header, char * fuse_in, char * fuse_out, APP_CB app_cb, void *app_ctxt)
{
    struct fuse_in_header * hdr = (struct fuse_in_header *)fuse_header;
    int op = hdr->opcode;

    printf("\033[33m+=+=+=+=+=+=+=+=  {fsdev_nfs_submit_request} FUNCTION CALLED and we are calling FUNCTION [%s]\033[0m\n", fuse_ll_ops[op].name);
    if (op != FUSE_UNLINK)
    {
        unsigned int xid = (unsigned int)(hdr->unique);
        assert(xid <= 0xffffffff);
        rpc_set_next_xid(nfs_get_rpc_context(fsdev->nfs), xid);
    }
    fuse_ll_ops[op].func(alloc_init_async_context(fsdev, fuse_header, fuse_in, fuse_out, app_cb, app_ctxt));
}


void
progress(struct nfs_fsdev * fsdev)
{
    fsdev->pfds[0].fd = nfs_get_fd(fsdev->nfs);
    fsdev->pfds[0].events = nfs_which_events(fsdev->nfs);

    if (poll(&fsdev->pfds[0], 1, 1) < 0)
    {
        printf("Poll failed");
        exit(17);
    }

    if (nfs_service(fsdev->nfs, fsdev->pfds[0].revents) < 0)
    {
        printf("nfs_service failed\n");
        exit(10);
    }
}

static void
complete(struct async_context * context, size_t len, int status)
{
    struct fuse_in_header * hdr_in = (struct fuse_in_header *)(context->fuse_header);
	struct fuse_out_header *hdr_out = (struct fuse_out_header *)(context->fuse_out);
    
    hdr_out->len = len;
    hdr_out->error = status;
    hdr_out->unique = hdr_in->unique;;
    context->app_cb(context->app_ctx, status); 
    free(context);
}

static void
lo_initilize_open_close_reply_struct(struct OpenCloseReply *open_close_reply_struct)
{
    open_close_reply_struct->header_xid = INIT_VALUE_XID;
    open_close_reply_struct->suffix_xid = INIT_VALUE_XID;
    compiler_barrier();
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

        //
        printf("=====\n");
        printf("THE DATA WE ARE RESTORING: \n");
        printf("struct xid = [%ld], struct value = [%ld]", open_close_reply_struct->suffix_xid, open_close_reply_struct->expected_ref_count);
        printf("struct INODE !!! = [%ld]", open_close_reply_struct->file_inode);
        printf("=====\n");

        // delete later

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
        global_test = false;
        second_test2 = false;
        lo_restore_open_close_reply_struct(open_close_reply_struct, fd, vfsdev);
    }
    compiler_barrier();
    return open_close_reply_struct;
}


struct nfs_fsdev *
nfs_fsdev_alloc_and_init(void)
{
    printf("+=+=+=+=+=+=+=+=  {spdk_fsdev_nfs_create} FUNCTION CALLED \n");
    struct nfs_fsdev * roman_fsdev = calloc(1, sizeof(*roman_fsdev));

    roman_fsdev->server = "127.0.0.1";
    roman_fsdev->export = "/VIRTUAL";
    char *filename = "/tmp/dataBase_log.bin";
    char *filename_reply_open_close = "/tmp/reply_open_close_log.bin";

    roman_fsdev->db = allocate_and_init_map(filename);
    roman_fsdev->open_close_reply_struct = lo_allocate_and_init_open_close_reply_struct(filename_reply_open_close, roman_fsdev);

    roman_fsdev->nfs = nfs_init_context();
    if (roman_fsdev->nfs == NULL)
    {
        printf("failed to init context\n");
        exit(10);
    }

    int ret = nfs_mount(roman_fsdev->nfs, roman_fsdev->server, roman_fsdev->export);
    if (ret != 0)
    {
        printf("Failed to start async nfs mount\n");
        exit(10);
    }

    if (!check_if_exist_by_left(roman_fsdev->db, 1))
    {
        printf("this is not in the map!!! \n");
        if (!lo_initialize_new_root_entry_and_insert_to_db(1, nfs_get_rootfh(roman_fsdev->nfs), roman_fsdev))
        {
            printf("Error: failed in inserting root file handle into map\n");
            exit(-1);
        }
    }
    else
    {
        printf("Warning: trying to insert ROOT FH to map, but already exist - we are restoring the data base...\n");
    }
    return roman_fsdev;
}
