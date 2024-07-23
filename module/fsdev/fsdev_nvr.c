/* SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */
#include "spdk/stdinc.h"
#include "spdk/event.h"
#include "spdk/dma.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "spdk/config.h"
#include "spdk/rpc.h"
#include "spdk/util.h"
#include "spdk/thread.h"
#include "spdk_internal/spdk_htable.h"
#include "nvr_mgr.h"
#include "nvr_rpc_clnt.h"
#include "fsdev_nvr.h"
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <sys/file.h>

#define OP_STATUS_ASYNC INT_MIN
#define DEFAULT_BDEV	"TODO"

#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif

/* See https://libfuse.github.io/doxygen/structfuse__conn__info.html */
#define TIME_GRAN (1)
#define DEFAULT_MAX_WRITE 0x00020000
#define DEFAULT_TIMEOUT_MS 86400000
#define DEFAULT_XATTR_ENABLED false
#define DIRLIST_SIZE 65536
#define INODES_HTABLE_SIZE 32

struct lo_cred {
	uid_t euid;
	gid_t egid;
};

/** Inode number type */
typedef uint64_t spdk_ino_t;

struct lo_map_elem {
	union {
		struct lo_inode *inode;
		//struct lo_dirp *dirp;
		struct lo_fh *lofh;
		ssize_t freelist;
	};
	bool in_use;
};

/* Maps FUSE fh or ino values to internal objects */
struct lo_map {
	struct lo_map_elem *elems;
	size_t nelems;
	ssize_t freelist;
};

struct lo_key {
	ino_t ino;
	dev_t dev;
};

struct lo_inode {
	struct nvr_fh fh;
	bool is_symlink;
	struct lo_key key;
	uint64_t refcount; /* protected by lo->mutex */
	spdk_ino_t fuse_ino;
	uint32_t fs_blksize;
	SPDK_HTABLE_ENTRY(lo_inode) link;
};

//struct lo_dirp {
//	struct nvr_fh fh;
//	DIR *dp;
//	struct dirent *entry;
//	off_t offset;
//};

struct lo_fh {
	struct nvr_fh fh;
	char* bdev_name;
};

struct nvr_fsdev {
	struct spdk_fsdev fsdev;
	struct nvrocks_rpc_client *nvrclnt;
	char *domain;
	char* mds_addr;
	uint16_t mds_port;
	bool xattr_enabled;
	int proc_self_fd;
	pthread_mutex_t mutex;
	SPDK_HTABLE_DECLARE(, lo_inode, INODES_HTABLE_SIZE) inodes; /* protected by nvr_fsdev->mutex */
	struct lo_map ino_map; /* protected by nvr_fsdev->mutex */
	//struct lo_map dirp_map; /* protected by nvr_fsdev->mutex */
	struct lo_map fh_map; /* protected by nvr_fsdev->mutex */
	struct lo_inode root;
	TAILQ_ENTRY(nvr_fsdev) tailq;
};

struct nvr_io_channel {
	struct spdk_nvr_mgr *mgr;
	char dirlist[DIRLIST_SIZE];
};

static TAILQ_HEAD(, nvr_fsdev) g_nvr_fsdev_head = TAILQ_HEAD_INITIALIZER(
			g_nvr_fsdev_head);

static struct spdk_memory_domain *g_memory_domain;

static inline struct nvr_fsdev *
fsdev_to_nvr_fsdev(struct spdk_fsdev *fsdev)
{
	return SPDK_CONTAINEROF(fsdev, struct nvr_fsdev, fsdev);
}

static int
is_dot_or_dotdot(const char *name)
{
	return name[0] == '.' && (name[1] == '\0' ||
				  (name[1] == '.' && name[2] == '\0'));
}

/* Is `path` a single path component that is not "." or ".."? */
static int
is_safe_path_component(const char *path)
{
	if (strchr(path, '/')) {
		return 0;
	}

	return !is_dot_or_dotdot(path);
}

static void
lo_map_init(struct lo_map *map)
{
	map->elems = NULL;
	map->nelems = 0;
	map->freelist = -1;
}

static void
lo_map_destroy(struct lo_map *map)
{
	free(map->elems);
}

static int
lo_map_grow(struct lo_map *map, size_t new_nelems)
{
	struct lo_map_elem *new_elems;
	size_t i;

	if (new_nelems <= map->nelems) {
		return 1;
	}

	new_elems = realloc(map->elems, sizeof(map->elems[0]) * new_nelems);
	if (!new_elems) {
		return 0;
	}

	for (i = map->nelems; i < new_nelems; i++) {
		new_elems[i].freelist = i + 1;
		new_elems[i].in_use = false;
	}
	new_elems[new_nelems - 1].freelist = -1;

	map->elems = new_elems;
	map->freelist = map->nelems;
	map->nelems = new_nelems;
	return 1;
}

static struct lo_map_elem *
lo_map_alloc_elem(struct lo_map *map)
{
	struct lo_map_elem *elem;

	if (map->freelist == -1 && !lo_map_grow(map, map->nelems + 256)) {
		return NULL;
	}

	elem = &map->elems[map->freelist];
	map->freelist = elem->freelist;

	elem->in_use = true;

	return elem;
}

static struct lo_map_elem *
lo_map_reserve(struct lo_map *map, size_t key)
{
	ssize_t *prev;

	if (!lo_map_grow(map, key + 1)) {
		return NULL;
	}

	for (prev = &map->freelist;
	     *prev != -1;
	     prev = &map->elems[*prev].freelist) {
		if (*prev == (ssize_t)key) {
			struct lo_map_elem *elem = &map->elems[key];

			*prev = elem->freelist;
			elem->in_use = true;
			return elem;
		}
	}
	return NULL;
}

static struct lo_map_elem *
lo_map_get(struct lo_map *map, size_t key)
{
	if (key >= map->nelems) {
		return NULL;
	}
	if (!map->elems[key].in_use) {
		return NULL;
	}
	return &map->elems[key];
}

static void
lo_map_remove(struct lo_map *map, size_t key)
{
	struct lo_map_elem *elem;

	if (key >= map->nelems) {
		return;
	}

	elem = &map->elems[key];
	if (!elem->in_use) {
		return;
	}

	elem->in_use = false;

	elem->freelist = map->freelist;
	map->freelist = key;
}

/* Assumes lo->mutex is held */
static ssize_t
lo_add_fh_mapping(struct nvr_fsdev *vfsdev, struct lo_fh *lofh)
{
	struct lo_map_elem *elem;

	elem = lo_map_alloc_elem(&vfsdev->fh_map);
	if (!elem) {
		return -1;
	}

	elem->lofh = lofh;
	return elem - vfsdev->fh_map.elems;
}

/* Assumes lo->mutex is held */
static ssize_t
lo_add_inode_mapping(struct nvr_fsdev *vfsdev, struct lo_inode *inode)
{
	struct lo_map_elem *elem;

	elem = lo_map_alloc_elem(&vfsdev->ino_map);
	if (!elem) {
		return -1;
	}

	elem->inode = inode;
	return elem - vfsdev->ino_map.elems;
}

static struct lo_inode *
lo_inode(struct nvr_fsdev *vfsdev, spdk_ino_t ino)
{
	struct lo_map_elem *elem;

	pthread_mutex_lock(&vfsdev->mutex);
	elem = lo_map_get(&vfsdev->ino_map, ino);
	pthread_mutex_unlock(&vfsdev->mutex);

	if (!elem) {
		return NULL;
	}

	return elem->inode;
}

static struct nvr_fh*
lo_fh(struct nvr_fsdev *vfsdev, spdk_ino_t ino)
{
	struct lo_inode *inode = lo_inode(vfsdev, ino);
	return inode ? &inode->fh : NULL;
}

static struct lo_inode *
lo_find_unsafe(struct nvr_fsdev *vfsdev, const struct nvr_fh *fh, const struct stat* attr)
{
	struct lo_inode *inode;
	size_t bkt;

	spdk_htable_foreach(&vfsdev->inodes, bkt, inode, link) {
		if (inode->key.ino == attr->st_ino && inode->key.dev == attr->st_dev) {
			assert(inode->refcount > 0);
			inode->refcount++;
			return inode;
		}
	}
	return NULL;
}

/*
static struct lo_inode *
lo_find(struct nvr_fsdev *vfsdev, const struct nvr_fh *fh, const struct stat *attr)
{
	struct lo_inode *inode;

	pthread_mutex_lock(&vfsdev->mutex);
	inode = lo_find_unsafe(vfsdev, fh, attr);
	pthread_mutex_unlock(&vfsdev->mutex);

	return inode;
}
*/

static void
unref_inode(struct nvr_fsdev *vfsdev, struct lo_inode *inode, uint64_t n)
{
	if (!inode) {
		return;
	}

	pthread_mutex_lock(&vfsdev->mutex);
	assert(inode->refcount >= n);
	inode->refcount -= n;
	if (!inode->refcount) {
		spdk_htable_del(inode, link);
		lo_map_remove(&vfsdev->ino_map, inode->fuse_ino);
		pthread_mutex_unlock(&vfsdev->mutex);
		//free(inode->fh.val);
		free(inode);
	} else {
		pthread_mutex_unlock(&vfsdev->mutex);
	}
}

static inline size_t
lo_inode_hkey(struct lo_inode *inode)
{
	return (size_t)(inode->key.ino * inode->key.dev) % INODES_HTABLE_SIZE;
}

/*
static struct lo_inode *
lookup_name(struct nvr_fsdev *vfsdev, spdk_ino_t parent, const char *name)
{
	int rc;
	struct nvr_fh out_fh;
	struct stat out_attr;

	struct nvr_fh* parent_fh = lo_fh(vfsdev, parent);
	if (!parent_fh) {
		return NULL;
	}
	rc = nvr_rpc_client_lookup(vfsdev->nvrclnt, parent_fh, name, &out_fh, &out_attr);
	if (rc) {
		return NULL;
	}

	struct lo_inode *ino = lo_find(vfsdev, &out_fh, &out_attr);
	//free(out_fh.val);
	return (ino);

}
*/

/*
static int
lo_parent_and_name(struct nvr_fsdev *vfsdev, struct lo_inode *inode,
		   char path[PATH_MAX], struct lo_inode **parent)
{
	// TODO
	return -1;
}
*/

/*
static int
utimensat_empty(struct nvr_fsdev *vfsdev, struct lo_inode *inode,
		const struct timespec *tv)
{
	// TODO
	return -1;
}
*/

static struct lo_fh*
lo_fi_fh(struct nvr_fsdev *vfsdev, uint64_t fi)
{
	struct lo_map_elem *elem;

	pthread_mutex_lock(&vfsdev->mutex);
	elem = lo_map_get(&vfsdev->fh_map, fi);
	pthread_mutex_unlock(&vfsdev->mutex);

	if (!elem) {
		return NULL;
	}

	return elem->lofh;
}

static int
lo_fill_getattr(struct nvr_fsdev* vfsdev, spdk_ino_t ino, struct stat *attr)
{
	int rc;
	struct lo_inode* inode;

	memset(attr, 0, sizeof(*attr));
	inode = lo_inode(vfsdev, ino);
	if (!inode) {
		SPDK_ERRLOG("lo_fill_getattr failed for (ino=%" PRIu64 ")\n", ino);
		return EBADF;
	}

	rc = nvr_rpc_client_get_attr(vfsdev->nvrclnt, &inode->fh, attr);
	if (rc) {
		SPDK_ERRLOG("Cannot get attributes from MDS for (ino=%" PRIu64 ", fh=[%d=0x%lx]). err=%d\n",
			ino, inode->fh.len, *(uint64_t*)(inode->fh.val), rc);
		return rc;
	}

	// TODO: Find out the exact blocks count
	attr->st_blocks = (attr->st_blksize > 0 ? (attr->st_size / attr->st_blksize) + 1 : 1);

	return 0;
}

static int
lo_getattr(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	int rc;
	struct nvr_fsdev *vfsdev = fsdev_to_nvr_fsdev(fsdev_io->fsdev);
	spdk_ino_t ino = fsdev_io->u_in.getattr.ino;
	uint64_t fh = fsdev_io->u_in.getattr.fh;

	UNUSED(fh);

	rc = lo_fill_getattr(vfsdev, ino, &fsdev_io->u_out.getattr.attr);
	if (rc) {
		return rc;
	}
	fsdev_io->u_out.getattr.attr_timeout_ms = DEFAULT_TIMEOUT_MS;

	SPDK_DEBUGLOG(fsdev_nvr, "GETATTR succeded for (ino=%" PRIu64 ")\n", ino);
	return 0;
}

static int
lo_opendir(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct nvr_fsdev* vfsdev = fsdev_to_nvr_fsdev(fsdev_io->fsdev);
	spdk_ino_t ino = fsdev_io->u_in.opendir.ino;
	struct lo_inode* inode;

	inode = lo_inode(vfsdev, ino);
	if (!inode) {
		SPDK_ERRLOG("OPENDIR: lo_inode failed for (ino=%" PRIu64 ")\n", ino);
		return EBADF;
	}

	SPDK_DEBUGLOG(fsdev_nvr, "OPENDIR: succeded for (ino=%" PRIu64 ")\n", ino);

	return 0;
}

static int
lo_releasedir(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct nvr_fsdev* vfsdev = fsdev_to_nvr_fsdev(fsdev_io->fsdev);
	spdk_ino_t ino = fsdev_io->u_in.releasedir.ino;
	struct lo_inode* inode;

	inode = lo_inode(vfsdev, ino);
	if (!inode) {
		SPDK_ERRLOG("RELEASEDIR: lo_inode failed for (ino=%" PRIu64 ")\n", ino);
		return EBADF;
	}

	SPDK_DEBUGLOG(fsdev_nvr, "RELEASEDIR: succeded for (ino=%" PRIu64 ")\n", ino);

	return 0;
}

static int
lo_do_lookup(struct nvr_fsdev *vfsdev, spdk_ino_t parent_ino, const char *name,
	     struct spdk_fsdev_entry *e)
{
	int rc;
	struct nvr_fh out_fh = {0};
	struct lo_inode *inode;

	memset(e, 0, sizeof(*e));
	e->attr_timeout_ms = DEFAULT_TIMEOUT_MS;
	e->entry_timeout_ms = DEFAULT_TIMEOUT_MS;

	struct nvr_fh *parent_fh = lo_fh(vfsdev, parent_ino);
	if (!parent_fh) {
		SPDK_ERRLOG("lookup file-handle for (parent_ino=%" PRIu64 ", name=%s) failed\n", parent_ino, name);
		return EBADF;
	}

	/* Do not allow escaping root directory */
	if (parent_fh == &vfsdev->root.fh && strcmp(name, "..") == 0) {
		name = ".";
	}

	rc = nvr_rpc_client_lookup(vfsdev->nvrclnt, parent_fh, name, &out_fh, &e->attr);
	if (rc) {
		SPDK_DEBUGLOG("Lookup file-handle for (parent_ino=%" PRIu64 ", name=%s, fh=[%d=0x%lx]) failed. err=%d\n",
			parent_ino, name, parent_fh->len, *(uint64_t*)(parent_fh->val), rc);
		return ENOENT;
	}

	// TODO: Find out the exact blocks count
	e->attr.st_blocks = (e->attr.st_blksize > 0 ? (e->attr.st_size / e->attr.st_blksize) + 1 : 1);

	pthread_mutex_lock(&vfsdev->mutex);
	inode = lo_find_unsafe(vfsdev, &out_fh, &e->attr);
	if (!inode) {
		inode = calloc(1, sizeof(struct lo_inode));
		if (!inode) {
			SPDK_ERRLOG("calloc(lo_inode)) failed\n");
			pthread_mutex_unlock(&vfsdev->mutex);
			return ENOMEM;
		}

		inode->is_symlink = false; // TODO
		inode->refcount = 1;
		inode->fh = out_fh;
		inode->key.ino = e->attr.st_ino;
		inode->key.dev = e->attr.st_dev;
		inode->fs_blksize = e->attr.st_blksize;

		inode->fuse_ino = lo_add_inode_mapping(vfsdev, inode);
		spdk_htable_add(&vfsdev->inodes, inode, link, lo_inode_hkey(inode));
	}
	pthread_mutex_unlock(&vfsdev->mutex);
	e->ino = inode->fuse_ino;

	SPDK_DEBUGLOG(fsdev_nvr, "LOOKUP: succeeded for (%s) in dir %" PRIu64 " (ino=%" PRIu64 ", fh=[%d=0x%lx])\n",
		      name, parent_ino, e->ino, inode->fh.len, *(uint64_t*)(inode->fh).val);
	return 0;
}

static void
lo_forget_one(struct nvr_fsdev* vfsdev, spdk_ino_t ino, uint64_t nlookup)
{
	struct lo_inode *inode;

	inode = lo_inode(vfsdev, ino);
	if (!inode) {
		return;
	}

	SPDK_DEBUGLOG(fsdev_nvr, "  forget %" PRIu64 " %" PRIu64 " -%" PRIu64 "\n",
		      ino, inode->refcount, nlookup);

	unref_inode(vfsdev, inode, nlookup);
}

static int
lo_lookup(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct nvr_fsdev *vfsdev = fsdev_to_nvr_fsdev(fsdev_io->fsdev);
	int err;
	spdk_ino_t parent_ino = fsdev_io->u_in.lookup.parent_ino;
	char *name = fsdev_io->u_in.lookup.name;

	SPDK_DEBUGLOG(fsdev_nvr, "lookup ino %" PRIu64 ", name %s" "\n", parent_ino, name);

	/* Don't use is_safe_path_component(), allow "." and ".." for NFS export
	 * support.
	 */
	if (strchr(name, '/')) {
		return EINVAL;
	}

	err = lo_do_lookup(vfsdev, parent_ino, name, &fsdev_io->u_out.lookup.entry);
	if (err) {
		SPDK_DEBUGLOG(fsdev_nvr, "lo_do_lookup(%s) failed with err=%d\n", name, err);
		return err;
	}

	return 0;
}

static int
lo_readdir(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
	struct nvr_fsdev* vfsdev = fsdev_to_nvr_fsdev(fsdev_io->fsdev);
	struct nvr_io_channel* ch = spdk_io_channel_get_ctx(_ch);
	struct lo_inode* inode;
	int rc, count;
	spdk_ino_t ino = fsdev_io->u_in.readdir.ino;
	uint64_t fi = fsdev_io->u_in.readdir.fh;
	uint64_t offset = fsdev_io->u_in.readdir.offset;
	size_t namelen;
	char* pos;

	inode = lo_inode(vfsdev, ino);
	if (!inode) {
		SPDK_ERRLOG("READDIR: cannot find inode for (ino=%" PRIu64 ", fi=%" PRIu64 ", offset=%" PRIu64 ")\n", ino, fi, offset);
		return EBADF;
	}

	// TODO: Support large dirs
	if (offset) {
		return 0;
	}

	memset(ch->dirlist, 0, DIRLIST_SIZE);
	rc = nvr_rpc_client_readdir(vfsdev->nvrclnt, &inode->fh, ch->dirlist, DIRLIST_SIZE-1);
	if (rc) {
		SPDK_ERRLOG("READDIR: failed to for (ino=%" PRIu64 ", fi=%" PRIu64 "). err=%d\n", ino, fi, rc);
		return rc;
	}

	for (count=0, namelen=0, pos=ch->dirlist; *pos; pos+=(namelen+1)) {
		spdk_ino_t entry_ino = 0;
		struct spdk_fsdev_entry* e = &fsdev_io->u_out.readdir.entry;
		memset(e, 0, sizeof(*e));

		namelen = strlen(pos);
		if (!is_dot_or_dotdot(pos)) {
			// TODO: parse the returned attributes instead of submitting a lookup request
			rc = lo_do_lookup(vfsdev, ino, pos, e);
			if (rc) {
				SPDK_ERRLOG("READDIR: lo_do_lookup for (ino=%" PRIu64 ", name=%s, namelen=%" PRIu64 ", count=%d) failed. err=%d\n",
					ino, pos, namelen, count, rc);
				return rc;
			}
			entry_ino = e->ino;
		}

		fsdev_io->u_out.readdir.name = pos;
		fsdev_io->u_out.readdir.offset = ++count;

		rc = fsdev_io->u_in.readdir.entry_clb(fsdev_io, fsdev_io->internal.caller_ctx);
		if (rc) {
			if (entry_ino != 0) {
				lo_forget_one(vfsdev, entry_ino, 1);
			}
			return rc;
		}
	}

	SPDK_DEBUGLOG(fsdev_nvr, "READDIR: succeded for (ino=%" PRIu64 ", fi=%" PRIu64 ", count=%d)\n", ino, fi, count);
	return 0;
}

static int
lo_forget(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct nvr_fsdev* vfsdev = fsdev_to_nvr_fsdev(fsdev_io->fsdev);
	lo_forget_one(vfsdev, fsdev_io->u_in.forget.ino, fsdev_io->u_in.forget.nlookup);

	return 0;
}

static int
lo_open(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct nvr_fsdev* vfsdev = fsdev_to_nvr_fsdev(fsdev_io->fsdev);
	struct nvr_fh* out_fh;
	struct nvr_stateid4 out_stid = { 0 };
	struct lo_fh* lofh=NULL;
	ssize_t fi = 0;
	uint64_t fsize;
	int err;
	spdk_ino_t ino = fsdev_io->u_in.open.ino;
	uint32_t flags = fsdev_io->u_in.open.flags;

	UNUSED(flags);

	SPDK_DEBUGLOG(fsdev_nvr, "lo_open(ino=%" PRIu64 ", flags=0x%08" PRIx32 ")\n", ino, flags);

	out_fh = lo_fh(vfsdev, ino);
	if (!out_fh) {
		err = EBADF;
		SPDK_ERRLOG("OPEN: invalid file-handle (ino=%" PRIu64 ")\n", ino);
		goto out_err;
	}

	err = nvr_rpc_client_open_file(vfsdev->nvrclnt, out_fh, &out_stid);
	if (err) {
		SPDK_ERRLOG("OPEN: failed for (ino=%" PRIu64 "). err=%d\n", ino, err);
		goto out_err;
	}

	// Allocate lofh entry
	lofh = calloc(1, sizeof(struct lo_fh));
	if (!lofh) {
		err = ENOMEM;
		SPDK_ERRLOG("OPEN: calloc(lo_fh)) failed for (ino=%" PRIu64 ")\n", ino);
		nvr_rpc_client_close_fh(vfsdev->nvrclnt, out_fh, &out_stid, &fsize);
		goto out_err;
	}

	lofh->fh = *out_fh;
	pthread_mutex_lock(&vfsdev->mutex);
	fi = lo_add_fh_mapping(vfsdev, lofh);
	pthread_mutex_unlock(&vfsdev->mutex);
	if (fi == -1) {
		err = EINVAL;
		SPDK_ERRLOG("OPEN: cannot add mapping for (ino=%" PRIu64 ")\n", ino);
		nvr_rpc_client_close_fh(vfsdev->nvrclnt, out_fh, &out_stid, &fsize);
		goto out_err;
	}

	fsdev_io->u_out.open.fh = fi;

	SPDK_DEBUGLOG(fsdev_nvr, "OPEN: succeded (ino=%" PRIu64 ", fi=%" PRIu64 ", fh=[%d=0x%lx])\n",
		ino, (uint64_t)fi, lofh->fh.len, *(uint64_t*)(lofh->fh).val);
	return 0;

out_err:
	if (lofh) {
		free(lofh);
	}
	return err;
}

static int
lo_flush(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	// TODO
	return 0;
}

static int
lo_setattr(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct nvr_fsdev* vfsdev = fsdev_to_nvr_fsdev(fsdev_io->fsdev);
	struct nvr_fh* fh;
	int rc;
	spdk_ino_t ino = fsdev_io->u_in.setattr.ino;
	uint64_t fi = fsdev_io->u_in.setattr.fh;
	uint32_t to_set = fsdev_io->u_in.setattr.to_set;
	struct stat* attr = &fsdev_io->u_in.setattr.attr;

	fh = lo_fh(vfsdev, ino);
	if (!fh) {
		SPDK_ERRLOG("SETATTR: lo_fh failed for (ino=%" PRIu64 ", fi=%" PRIu64 ", flags=0x%x)\n",
			ino, fi, to_set);
		return EBADF;
	}

	if (to_set & FSDEV_SET_ATTR_SIZE) {
		rc = nvr_rpc_client_set_size(vfsdev->nvrclnt, fh, attr->st_size);
		if (rc) {
			SPDK_ERRLOG("SETATTR: failed for (ino=%" PRIu64 ", fi=%" PRIu64 ", fh=[%d=0x%lx], flags=0x%x, size=%" PRIu64 "). err=%d\n",
				ino, fi, fh->len, *(uint64_t*)(fh->val), to_set, attr->st_size, rc);
			return rc;
		}
	}

	fsdev_io->u_out.setattr.attr_timeout_ms = DEFAULT_TIMEOUT_MS;

	SPDK_DEBUGLOG(fsdev_nvr, "SETATTR succeded for (ino=%" PRIu64 ", fi=%" PRIu64 ", fh=[%d=0x%lx], flags=0x%x)\n",
		ino, fi, fh->len, *(uint64_t*)(fh->val), to_set);

	return 0;
}

static int
lo_create(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct nvr_fsdev *vfsdev = fsdev_to_nvr_fsdev(fsdev_io->fsdev);
	ssize_t fi = 0;
	int err;
	spdk_ino_t parent_ino = fsdev_io->u_in.create.parent_ino;
	const char *name = fsdev_io->u_in.create.name;
	uint32_t mode = fsdev_io->u_in.create.mode;
	uint32_t flags = fsdev_io->u_in.create.flags;
	uint32_t umask = fsdev_io->u_in.create.umask;
	struct lo_fh* lofh = NULL;
	struct nvr_fh out_fh = {0};
	struct nvr_stateid4 out_stid = {0};

	UNUSED(mode);
	UNUSED(flags);
	UNUSED(umask);

	SPDK_DEBUGLOG(fsdev_nvr, "lo_create(parent=%" PRIu64 ", name=%s)\n",
		      parent_ino, name);

	if (!is_safe_path_component(name)) {
		SPDK_ERRLOG("CREATE: %s not a safe component\n", name);
		return EINVAL;
	}

	/* Promote O_WRONLY to O_RDWR. Otherwise later mmap(PROT_WRITE) fails */
	//if ((flags & O_ACCMODE) == O_WRONLY) {
	//	flags &= ~O_ACCMODE;
	//	flags |= O_RDWR;
	//}

	struct nvr_fh *parent_fh = lo_fh(vfsdev, parent_ino);
	if (!parent_fh) {
		return EBADF;
	}

	err = nvr_rpc_client_open(vfsdev->nvrclnt, parent_fh, name, &out_stid, &out_fh, true);
	if (err) {
		SPDK_ERRLOG("CREATE: open failed with %d\n", err);
		goto out_err;
	}

	// Allocate lofh entry
	lofh = calloc(1, sizeof(struct lo_fh));
	if (!lofh) {
		err = ENOMEM;
		SPDK_ERRLOG("CREATE: calloc(lo_fh)) failed for (parent=%" PRIu64 ", name=%s)\n", parent_ino, name);
		goto out_err;
	}

	lofh->fh = out_fh;
	pthread_mutex_lock(&vfsdev->mutex);
	fi = lo_add_fh_mapping(vfsdev, lofh);
	pthread_mutex_unlock(&vfsdev->mutex);
	if (fi == -1) {
		err = EINVAL;
		uint64_t newsize = 0;
		nvr_rpc_client_close_fh(vfsdev->nvrclnt, &out_fh, &out_stid, &newsize);
		SPDK_ERRLOG("CREATE: cannot add mapping for (parent=%" PRIu64 ", name=%s)\n", parent_ino, name);
		goto out_err;
	}

	err = lo_do_lookup(vfsdev, parent_ino, name, &fsdev_io->u_out.create.entry);
	if (err) {
		SPDK_ERRLOG("CREATE: lookup failed for (parent=%" PRIu64 ", name=%s, fi=%" PRIu64 "). err=%d\n",
			parent_ino, name, fi, err);
		goto out_err;
	}

	SPDK_DEBUGLOG(fsdev_nvr, "CREATE: succeded (parent=%" PRIu64 ", name=%s, fi=%" PRIu64 ")\n", parent_ino, name, (uint64_t)fi);

	fsdev_io->u_out.create.fh = fi;

	return 0;

out_err:
	if (lofh) {
		free(lofh);
	}
	return err;
}

static int
lo_release(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct nvr_fsdev *vfsdev = fsdev_to_nvr_fsdev(fsdev_io->fsdev);
	struct lo_fh *lofh;
	spdk_ino_t ino = fsdev_io->u_in.release.ino;
	uint64_t fi = fsdev_io->u_in.release.fh;



	lofh = lo_fi_fh(vfsdev, fi);
	if (!lofh) {
		SPDK_ERRLOG("RELEASE: lo_fi_fh failed for (ino=%" PRIu64 ", fi=%" PRIu64 ")\n", ino, fi);
		return EBADF;
	}

	pthread_mutex_lock(&vfsdev->mutex);
	lo_map_remove(&vfsdev->fh_map, fi);
	pthread_mutex_unlock(&vfsdev->mutex);

	SPDK_DEBUGLOG(fsdev_nvr, "RELEASE succeded (fi=%" PRIu64 " , fh=[%d=0x%lx])\n", fi, lofh->fh.len, *(uint64_t*)(lofh->fh).val);
	free(lofh);

	return 0;
}

static void
lo_read_cb(struct spdk_bdev_io* bdev_io, bool success, void* cb_arg)
{
	struct spdk_fsdev_io* fsdev_io = cb_arg;

	fsdev_io->u_out.read.data_size = fsdev_io->u_in.read.size;

	spdk_bdev_free_io(bdev_io);
	spdk_fsdev_io_complete(fsdev_io, !success);
}

static int
lo_read(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
	int rc;
	struct nvr_fsdev* vfsdev = fsdev_to_nvr_fsdev(fsdev_io->fsdev);
	struct nvr_io_channel* ch = spdk_io_channel_get_ctx(_ch);
	struct lo_fh* lofh;
	spdk_ino_t ino = fsdev_io->u_in.read.ino;
	uint64_t fi = fsdev_io->u_in.read.fh;
	size_t size = fsdev_io->u_in.read.size;
	uint64_t offs = fsdev_io->u_in.read.offs;
	uint32_t flags = fsdev_io->u_in.read.flags;
	struct iovec* outvec = fsdev_io->u_in.read.iov;
	uint32_t outcnt = fsdev_io->u_in.read.iovcnt;

	/* we don't suport the memory domains at the moment */
	assert(!fsdev_io->u_in.read.opts || !fsdev_io->u_in.read.opts->memory_domain);

	UNUSED(ino);
	UNUSED(flags);

	if (!outcnt || !outvec) {
		SPDK_ERRLOG("READ: bad outvec: iov=%p outcnt=%" PRIu32 " for (ino=%" PRIu64 ", fi=%" PRIu64 ")\n", outvec, outcnt, ino, fi);
		return EINVAL;
	}

	lofh = lo_fi_fh(vfsdev, fi);
	if (!lofh) {
		SPDK_ERRLOG("READ: lo_fi_fh failed for (ino=%" PRIu64 ", fi=%" PRIu64 ")\n", ino, fi);
		return EBADF;
	}

	// Check if the layout already exits
	if (!lofh->bdev_name) {
		struct nvr_stateid4 stid;
		uint64_t loffs = offs;
		uint32_t lsize = size;
		struct lo_inode *inode = lo_inode(vfsdev, ino);
		if (!inode) {
			SPDK_ERRLOG("READ: lo_inode failed for (ino=%" PRIu64 ", fi=%" PRIu64 ")\n", ino, fi);
			return EBADF;
		}

		// Make sure offs and size are aligned to file-system block-size
		if (loffs % inode->fs_blksize > 0) {
			uint64_t shift_cnt = spdk_u64log2(inode->fs_blksize);
			loffs &= (~((1 << shift_cnt) - 1));
		}

		if (lsize % inode->fs_blksize > 0) {
			uint32_t shift_cnt = spdk_u32log2(inode->fs_blksize);
			lsize += inode->fs_blksize;
			lsize &= (~((1 << shift_cnt) - 1));
		}

		rc = nvr_rpc_client_layoutget(vfsdev->nvrclnt, &lofh->fh, &stid, false, loffs, lsize);
		if (rc) {
			SPDK_ERRLOG("READ: cannot retrieve file layout for (ino=%" PRIu64 ", fi=%" PRIu64 ", offs=%" PRIu64 "|%" PRIu64 ", size=%d|%" PRIu64 ").err = % d\n",
				ino, fi, loffs, offs, lsize, size, rc);
			return EINVAL;
		}
		// TODO: Extract the block device name from the stid
		lofh->bdev_name = DEFAULT_BDEV;
	}

	if (!lofh->bdev_name) {
		SPDK_ERRLOG("READ: bdev is not available for (ino=%" PRIu64 ", fi = %" PRIu64 ")\n", ino, fi);
		return EBADF;
	}

	rc = spdk_nvr_mgr_read(ch->mgr, lofh->bdev_name, lo_read_cb, fsdev_io);
	return rc;
}

static void
lo_write_cb(struct spdk_bdev_io* bdev_io, bool success, void* cb_arg)
{
	struct spdk_fsdev_io* fsdev_io = cb_arg;

	fsdev_io->u_out.write.data_size = fsdev_io->u_in.write.size;

	spdk_bdev_free_io(bdev_io);
	spdk_fsdev_io_complete(fsdev_io, !success);
}

static int
lo_write(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
	int rc;
	struct nvr_fsdev* vfsdev = fsdev_to_nvr_fsdev(fsdev_io->fsdev);
	struct nvr_io_channel* ch = spdk_io_channel_get_ctx(_ch);
	struct lo_fh* lofh;
	spdk_ino_t ino = fsdev_io->u_in.write.ino;
	uint64_t fi = fsdev_io->u_in.write.fh;
	size_t size = fsdev_io->u_in.write.size;
	uint64_t offs = fsdev_io->u_in.write.offs;
	uint32_t flags = fsdev_io->u_in.write.flags;
	const struct iovec* invec = fsdev_io->u_in.write.iov;
	uint32_t incnt = fsdev_io->u_in.write.iovcnt;

	/* we don't suport the memory domains at the moment */
	assert(!fsdev_io->u_in.write.opts || !fsdev_io->u_in.write.opts->memory_domain);

	UNUSED(flags);

	if (!incnt || !invec) { /* there should be at least one iovec with data */
		SPDK_ERRLOG("WRITE: bad invec: iov=%p cnt=%" PRIu32 "\n", invec, incnt);
		return EINVAL;
	}

	lofh = lo_fi_fh(vfsdev, fi);
	if (!lofh) {
		SPDK_ERRLOG("WRITE: lo_fi_fh failed for (ino=%" PRIu64 ", fi=%" PRIu64 ")\n", ino, fi);
		return EBADF;
	}

	// Check if the layout already exits
	if (!lofh->bdev_name) {
		struct nvr_stateid4 stid;
		uint64_t loffs = offs;
		uint32_t lsize = size;

		struct lo_inode* inode = lo_inode(vfsdev, ino);
		if (!inode) {
			SPDK_ERRLOG("WRITE: lo_inode failed for (ino=%" PRIu64 ", fi=%" PRIu64 ")\n", ino, fi);
			return EBADF;
		}

		// Make sure offs and size are aligned to file-system block-size
		if (loffs % inode->fs_blksize > 0) {
			uint64_t shift_cnt = spdk_u64log2(inode->fs_blksize);
			loffs &= (~((1 << shift_cnt) - 1));
		}

		if (lsize % inode->fs_blksize > 0) {
			uint32_t shift_cnt = spdk_u32log2(inode->fs_blksize);
			lsize += inode->fs_blksize;
			lsize &= (~((1 << shift_cnt) - 1));
		}

		rc = nvr_rpc_client_layoutget(vfsdev->nvrclnt, &lofh->fh, &stid, true, loffs, lsize);
		if (rc) {
			SPDK_ERRLOG("WRITE: cannot retrieve file layout for (ino=%" PRIu64 ", fi=%" PRIu64 ", offs=%" PRIu64 "|%" PRIu64 ", size=%d|%" PRIu64 "). err=%d\n",
				ino, fi, loffs, offs, lsize, size, rc);
			rc = 0;
			//return EINVAL;
		}
		// TODO: Extract the block device name from the stid
		lofh->bdev_name = DEFAULT_BDEV;
	}

	if (!lofh->bdev_name) {
		SPDK_ERRLOG("WRITE: bdev is not available for (ino=%" PRIu64 ", fi=%" PRIu64 ")\n", ino, fi);
		return EBADF;
	}

	rc = spdk_nvr_mgr_write(ch->mgr, lofh->bdev_name, lo_write_cb, fsdev_io);
	return rc;
}

static int
lo_readlink(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	// TODO
	return -1;
}

static int
lo_statfs(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct nvr_fsdev* vfsdev = fsdev_to_nvr_fsdev(fsdev_io->fsdev);
	spdk_ino_t ino = fsdev_io->u_in.statfs.ino;
	int rc;

	struct nvr_fh* fh4 = lo_fh(vfsdev, ino);
	if (!fh4) {
		SPDK_ERRLOG("STATVFS: lo_fh failed for (ino=%" PRIu64 ")\n", ino);
		return EBADF;
	}

	rc = nvr_rpc_client_get_fsattr(vfsdev->nvrclnt, fh4, &fsdev_io->u_out.statfs.stbuf);
	if (rc) {
		SPDK_ERRLOG("STATVFS: get_fsattr failed for (ino=%" PRIu64 "). err=%d\n", ino, rc);
		return rc;
	}

	return rc;
}

static int
lo_mknod_symlink(struct spdk_fsdev_io *fsdev_io, spdk_ino_t parent_ino, const char *name,
		 mode_t mode, dev_t rdev, const char *link, uid_t euid, gid_t egid, struct spdk_fsdev_entry *e)
{
	struct nvr_fsdev* vfsdev = fsdev_to_nvr_fsdev(fsdev_io->fsdev);
	struct nvr_fh* parent_fh;
	int rc=0;

	if (!is_safe_path_component(name)) {
		SPDK_ERRLOG("%s isn't safe (parent_ino=%" PRIu64 ")\n", name, parent_ino);
		return EINVAL;
	}

	parent_fh = lo_fh(vfsdev, parent_ino);
	if (!parent_fh) {
		SPDK_ERRLOG("cannot find parent dir (parent_ino=%" PRIu64 ", name=%s)\n", parent_ino, name);
		return EBADF;
	}

	if (S_ISDIR(mode)) {
		rc = nvr_rpc_client_mkdir(vfsdev->nvrclnt, parent_fh, name);
	}
	else if (S_ISLNK(mode)) {
		// TODO
	}
	else {
		struct nvr_fh out_fh = { 0 };
		struct nvr_stateid4 out_stid = { 0 };
		rc = nvr_rpc_client_open(vfsdev->nvrclnt, parent_fh, name, &out_stid, &out_fh, true);
	}

	if (rc) {
		SPDK_ERRLOG("cannot mkdir/symlink/mknod for (parent_ino=%" PRIu64 ", name=%s) (err=%d)\n", parent_ino, name, rc);
		return rc;
	}

	rc = lo_do_lookup(vfsdev, parent_ino, name, e);
	if (rc) {
		SPDK_NOTICELOG("lookup failed for (parent_ino=%" PRIu64 ", name=%s). err=%d\n", parent_ino, name, rc);
		return rc;
	}

	SPDK_DEBUGLOG(fsdev_nvr, "lo_mknod_symlink succeded %" PRIu64 " / %s -> %" PRIu64 "\n",
		parent_ino, name, e->ino);

	return 0;
}

static int
lo_mknod(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	spdk_ino_t parent_ino = fsdev_io->u_in.mknod.parent_ino;
	char* name = fsdev_io->u_in.mknod.name;
	mode_t mode = fsdev_io->u_in.mknod.mode;
	dev_t rdev = fsdev_io->u_in.mknod.rdev;
	uid_t euid = fsdev_io->u_in.mknod.euid;
	gid_t egid = fsdev_io->u_in.mknod.egid;
	struct spdk_fsdev_entry* e = &fsdev_io->u_out.mknod.entry;

	return lo_mknod_symlink(fsdev_io, parent_ino, name, mode, rdev, NULL, euid, egid, e);
}

static int
lo_mkdir(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	spdk_ino_t parent_ino = fsdev_io->u_in.mkdir.parent_ino;
	char *name = fsdev_io->u_in.mkdir.name;
	mode_t mode = fsdev_io->u_in.mkdir.mode;
	uid_t euid = fsdev_io->u_in.mkdir.euid;
	gid_t egid = fsdev_io->u_in.mkdir.egid;
	struct spdk_fsdev_entry *e = &fsdev_io->u_out.mkdir.entry;

	return lo_mknod_symlink(fsdev_io, parent_ino, name, S_IFDIR | mode, 0, NULL, euid, egid, e);
}

static int
lo_symlink(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	spdk_ino_t parent_ino = fsdev_io->u_in.symlink.parent_ino;
	char* target = fsdev_io->u_in.symlink.target;
	char* linkpath = fsdev_io->u_in.symlink.linkpath;
	uid_t euid = fsdev_io->u_in.symlink.euid;
	gid_t egid = fsdev_io->u_in.symlink.egid;
	struct spdk_fsdev_entry* e = &fsdev_io->u_out.symlink.entry;

	return lo_mknod_symlink(fsdev_io, parent_ino, target, S_IFLNK, 0, linkpath, euid, egid, e);
}

static int
lo_unlink(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct nvr_fsdev *vfsdev = fsdev_to_nvr_fsdev(fsdev_io->fsdev);	
	spdk_ino_t parent_ino = fsdev_io->u_in.unlink.parent_ino;
	char *name = fsdev_io->u_in.unlink.name;
	int rc;

	if (!is_safe_path_component(name)) {
		SPDK_ERRLOG("UNLINK: %s isn't safe (parent_ino=%" PRIu64 ")\n", name, parent_ino);
		return EINVAL;
	}

	struct nvr_fh* parent_fh = lo_fh(vfsdev, parent_ino);
	if (!parent_fh) {
		SPDK_ERRLOG("UNLINK: lo_fh failed for (parent_ino=%" PRIu64 ", name=%s)\n", parent_ino, name);
		return EBADF;
	}

	rc = nvr_rpc_client_remove(vfsdev->nvrclnt, parent_fh, name);
	if (rc) {
		SPDK_ERRLOG("UNLINK: remove failed for (parent_ino=%" PRIu64 ", name=%s). err=%d\n", parent_ino, name, rc);
		return rc;
	}

	SPDK_DEBUGLOG(fsdev_nvr, "UNLINK: succeded %" PRIu64 " / %s -> %" PRIu64 "\n",
		parent_ino, name, e->ino);


	return 0;
}

static int
lo_rmdir(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct nvr_fsdev *vfsdev = fsdev_to_nvr_fsdev(fsdev_io->fsdev);
	spdk_ino_t parent_ino = fsdev_io->u_in.rmdir.parent_ino;
	char *name = fsdev_io->u_in.rmdir.name;
	int rc;

	if (!is_safe_path_component(name)) {
		SPDK_ERRLOG("RDMIR: %s isn't safe (parent_ino=%" PRIu64 ")\n", name, parent_ino);
		return EINVAL;
	}

	struct nvr_fh* parent_fh = lo_fh(vfsdev, parent_ino);
	if (!parent_fh) {
		SPDK_ERRLOG("RMDIR: lo_fh failed for (parent_ino=%" PRIu64 ", name=%s)\n", parent_ino, name);
		return EBADF;
	}

	rc = nvr_rpc_client_remove(vfsdev->nvrclnt, parent_fh, name);
	if (rc) {
		SPDK_ERRLOG("RMDIR: remove failed for (parent_ino=%" PRIu64 ", name=%s). err=%d\n", parent_ino, name, rc);
		return rc;
	}

	SPDK_DEBUGLOG(fsdev_nvr, "RMDIR: succeded %" PRIu64 " / %s -> %" PRIu64 "\n",
		parent_ino, name, e->ino);


	return 0;
}

static int
lo_rename(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	// TODO
	return EINVAL;
}

static int
lo_link(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	// TODO
	return EINVAL;
}

static int
lo_fsync(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	// TODO
	return 0;
}

static int
lo_setxattr(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct nvr_fsdev* vfsdev = fsdev_to_nvr_fsdev(fsdev_io->fsdev);

	if (!vfsdev->xattr_enabled) {
		SPDK_INFOLOG(fsdev_nvr, "xattr is disabled by config\n");
		return ENOSYS;
	}

	// TODO
	return ENOTSUP;
}

static int
lo_getxattr(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct nvr_fsdev* vfsdev = fsdev_to_nvr_fsdev(fsdev_io->fsdev);

	if (!vfsdev->xattr_enabled) {
		SPDK_INFOLOG(fsdev_nvr, "xattr is disabled by config\n");
		return ENOSYS;
	}

	// TODO
	return ENOTSUP;
}

static int
lo_listxattr(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct nvr_fsdev* vfsdev = fsdev_to_nvr_fsdev(fsdev_io->fsdev);

	if (!vfsdev->xattr_enabled) {
		SPDK_INFOLOG(fsdev_nvr, "xattr is disabled by config\n");
		return ENOSYS;
	}

	// TODO
	return ENOTSUP;
}

static int
lo_removexattr(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct nvr_fsdev* vfsdev = fsdev_to_nvr_fsdev(fsdev_io->fsdev);

	if (!vfsdev->xattr_enabled) {
		SPDK_INFOLOG(fsdev_nvr, "xattr is disabled by config\n");
		return ENOSYS;
	}

	// TODO
	return ENOTSUP;
}

static int
lo_fsyncdir(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	// TODO
	return 0;
}

static int
lo_flock(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	// TODO
	return 0;
}

static int
lo_fallocate(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	// TODO
	return ENOSYS;
}

static int
lo_copy_file_range(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	// TODO
	return ENOSYS;
}

static int
lo_abort(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
	// TODO
	return 0;
}

static int
nvr_fsdev_create_cb(void *io_device, void *ctx_buf)
{
	struct nvr_io_channel *ch = ctx_buf;
	struct spdk_thread *thread = spdk_get_thread();

	ch->mgr = spdk_nvr_mgr_create();
	if (!ch->mgr) {
		SPDK_ERRLOG("Failed to init nvr manager for IO channel: thread=%s, thread id %" PRIu64 "\n",
			spdk_thread_get_name(thread), spdk_thread_get_id(thread));
		return ENOMEM;
	}

	SPDK_DEBUGLOG(fsdev_nvr, "Created nvr fsdev IO channel: thread %s, thread id %" PRIu64 "\n",
		spdk_thread_get_name(thread), spdk_thread_get_id(thread));
	return 0;
}

static void
nvr_fsdev_destroy_cb(void *io_device, void *ctx_buf)
{
	struct nvr_io_channel *ch = ctx_buf;
	struct spdk_thread *thread = spdk_get_thread();
	UNUSED(thread);

	spdk_nvr_mgr_delete(ch->mgr);
	ch->mgr = NULL;

	SPDK_DEBUGLOG(fsdev_nvr, "Destroyed nvr fsdev IO channel: thread %s, thread id %" PRIu64 "\n",
		spdk_thread_get_name(thread), spdk_thread_get_id(thread));
}

static int
fsdev_nvr_initialize(void)
{
	/*
	 * We need to pick some unique address as our "io device" - so just use the
	 *  address of the global tailq.
	 */
	spdk_io_device_register(&g_nvr_fsdev_head,
				nvr_fsdev_create_cb, nvr_fsdev_destroy_cb,
				sizeof(struct nvr_io_channel), "nvr_fsdev");

	return 0;
}

static void
_fsdev_nvr_finish_cb(void *arg)
{
	/* @todo: handle async module fini */
	/* spdk_fsdev_module_fini_done(); */
}

static void
fsdev_nvr_finish(void)
{
	spdk_io_device_unregister(&g_nvr_fsdev_head, _fsdev_nvr_finish_cb);
}

static int
fsdev_nvr_get_ctx_size(void)
{
	return sizeof(struct nvr_fsdev);
}

static struct spdk_fsdev_module nvr_fsdev_module = {
	.name = "nvr",
	.module_init = fsdev_nvr_initialize,
	.module_fini = fsdev_nvr_finish,
	.get_ctx_size	= fsdev_nvr_get_ctx_size,
};

SPDK_FSDEV_MODULE_REGISTER(nvr, &nvr_fsdev_module);

static void
fsdev_nvr_free(struct nvr_fsdev *vfsdev)
{
	if (vfsdev->proc_self_fd != -1) {
		close(vfsdev->proc_self_fd);
	}

	if (vfsdev->nvrclnt != NULL) {
		nvr_rpc_client_destroy(vfsdev->nvrclnt);
		vfsdev->nvrclnt = NULL;
	}

	free(vfsdev->fsdev.name);
	free(vfsdev->domain);
	free(vfsdev->mds_addr);

	free(vfsdev);
}

static int
fsdev_nvr_destruct(void *ctx)
{
	struct nvr_fsdev *vfsdev = ctx;
	size_t bkt;
	struct lo_inode *inode, *tmp;
	struct lo_map_elem* elems = vfsdev->fh_map.elems;

	TAILQ_REMOVE(&g_nvr_fsdev_head, vfsdev, tailq);

	for (size_t i = 0; i < vfsdev->fh_map.nelems; i++) {
		if (elems[i].in_use && elems[i].lofh) {
			//free(elems[i].lofh->fh.val);
			free(elems[i].lofh);
		}
		elems[i].in_use = false;
	}

	lo_map_destroy(&vfsdev->fh_map);
	//lo_map_destroy(&vfsdev->dirp_map);
	lo_map_destroy(&vfsdev->ino_map);

	spdk_htable_foreach_safe(&vfsdev->inodes, bkt, inode, link, tmp) {
		spdk_htable_del(inode, link);
		//free(inode->fh.val);
		free(inode);
	}

	pthread_mutex_destroy(&vfsdev->mutex);

	fsdev_nvr_free(vfsdev);
	return 0;
}

typedef int (*fsdev_op_handler_func)(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io);

static fsdev_op_handler_func handlers[] = {
	[SPDK_FSDEV_OP_LOOKUP] = lo_lookup,
	[SPDK_FSDEV_OP_FORGET] = lo_forget,
	[SPDK_FSDEV_OP_GETATTR] = lo_getattr,
	[SPDK_FSDEV_OP_SETATTR] = lo_setattr,
	[SPDK_FSDEV_OP_READLINK] = lo_readlink,
	[SPDK_FSDEV_OP_SYMLINK] = lo_symlink,
	[SPDK_FSDEV_OP_MKNOD] = lo_mknod,
	[SPDK_FSDEV_OP_MKDIR] = lo_mkdir,
	[SPDK_FSDEV_OP_UNLINK] = lo_unlink,
	[SPDK_FSDEV_OP_RMDIR] = lo_rmdir,
	[SPDK_FSDEV_OP_RENAME] = lo_rename,
	[SPDK_FSDEV_OP_LINK] = lo_link,
	[SPDK_FSDEV_OP_OPEN] = lo_open,
	[SPDK_FSDEV_OP_READ] = lo_read,
	[SPDK_FSDEV_OP_WRITE] = lo_write,
	[SPDK_FSDEV_OP_STATFS] =  lo_statfs,
	[SPDK_FSDEV_OP_RELEASE] = lo_release,
	[SPDK_FSDEV_OP_FSYNC] = lo_fsync,
	[SPDK_FSDEV_OP_SETXATTR] =  lo_setxattr,
	[SPDK_FSDEV_OP_GETXATTR] =  lo_getxattr,
	[SPDK_FSDEV_OP_LISTXATTR] = lo_listxattr,
	[SPDK_FSDEV_OP_REMOVEXATTR] =  lo_removexattr,
	[SPDK_FSDEV_OP_FLUSH] =  lo_flush,
	[SPDK_FSDEV_OP_OPENDIR] =  lo_opendir,
	[SPDK_FSDEV_OP_READDIR] =  lo_readdir,
	[SPDK_FSDEV_OP_RELEASEDIR] = lo_releasedir,
	[SPDK_FSDEV_OP_FSYNCDIR] = lo_fsyncdir,
	[SPDK_FSDEV_OP_FLOCK] = lo_flock,
	[SPDK_FSDEV_OP_CREATE] = lo_create,
	[SPDK_FSDEV_OP_ABORT] = lo_abort,
	[SPDK_FSDEV_OP_FALLOCATE] = lo_fallocate,
	[SPDK_FSDEV_OP_COPY_FILE_RANGE] = lo_copy_file_range,
};

static void
fsdev_nvr_submit_request(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	int status;
	enum spdk_fsdev_op op = spdk_fsdev_io_get_op(fsdev_io);

	assert(op >= 0 && op < __SPDK_FSDEV_OP_LAST);

	status = handlers[op](ch, fsdev_io);
	if (status != OP_STATUS_ASYNC) {
		spdk_fsdev_io_complete(fsdev_io, status);
	}
}

static struct spdk_io_channel *
fsdev_nvr_get_io_channel(void *ctx)
{
	return spdk_get_io_channel(&g_nvr_fsdev_head);
}

static int
fsdev_nvr_negotiate_opts(void *ctx, struct spdk_fsdev_instance_opts *opts)
{
	struct nvr_fsdev *vfsdev = ctx;
	UNUSED(vfsdev);

	assert(opts != 0);
	assert(opts->opts_size != 0);

	/* The NVR doesn't apply any additional restrictions, so we just accept the requested opts */
	SPDK_DEBUGLOG(fsdev_nvr,
		      "nvr filesystem %s: opts updated: writeback_cache=%" PRIu8 " max_write=%" PRIu32 ")\n",
		      vfsdev->fsdev.name, opts->writeback_cache_enabled, opts->max_write);

	return 0;
}

static void
fsdev_nvr_write_config_json(struct spdk_fsdev *fsdev, struct spdk_json_write_ctx *w)
{
	struct nvr_fsdev *vfsdev = fsdev_to_nvr_fsdev(fsdev);

	spdk_json_write_object_begin(w);
	spdk_json_write_named_string(w, "method", "fsdev_nvr_create");
	spdk_json_write_named_object_begin(w, "params");
	spdk_json_write_named_string(w, "name", fsdev->name);
	spdk_json_write_named_string(w, "domain", vfsdev->domain);
	spdk_json_write_named_string(w, "mds_addr", vfsdev->mds_addr);
	spdk_json_write_named_uint16(w, "mds_port", vfsdev->mds_port);
	spdk_json_write_named_uint8(w, "xattr_enabled", vfsdev->xattr_enabled ? 1 : 0);
	spdk_json_write_object_end(w); /* params */
	spdk_json_write_object_end(w);
}

static int
fsdev_nvr_get_memory_domains(void* ctx, struct spdk_memory_domain** domains, int array_size) {
	if (!domains) {
		if (array_size == 0) { return 1; }
		return -EINVAL;
	}

	if (array_size <= 0) {
		return -EINVAL;
	}

	domains[0] = g_memory_domain;
	return 1;
}

static const struct spdk_fsdev_fn_table nvr_fn_table = {
	.destruct			= fsdev_nvr_destruct,
	.submit_request		= fsdev_nvr_submit_request,
	.get_io_channel		= fsdev_nvr_get_io_channel,
	.negotiate_opts		= fsdev_nvr_negotiate_opts,
	.write_config_json	= fsdev_nvr_write_config_json,
	.get_memory_domains = fsdev_nvr_get_memory_domains,
};

static int
setup_clnt(struct nvr_fsdev *vfsdev)
{
	uint32_t n_cpus = spdk_env_get_core_count();
	vfsdev->nvrclnt = nvr_rpc_client_create(vfsdev->domain, vfsdev->mds_addr, vfsdev->mds_port, (uint8_t)n_cpus);

	if (!nvr_rpc_client_is_connected(vfsdev->nvrclnt)) {
		SPDK_ERRLOG("Cannot connect to the MDS %s:%d\n", vfsdev->mds_addr, vfsdev->mds_port);
		return -1;
	}

	vfsdev->root.fuse_ino = SPDK_FUSE_ROOT_ID;
	const struct nvr_fh* rfh = nvr_rpc_client_get_root_fh(vfsdev->nvrclnt);
	if (!rfh) {
		SPDK_ERRLOG("Cannot retrieve root file-handle\n");
		return -1;
	}
	vfsdev->root.fh = *rfh;

	// TODO: the ino and dev should be extracted from the root_fh
	vfsdev->root.key.ino = SPDK_FUSE_ROOT_ID;
	vfsdev->root.key.dev = 1;
	vfsdev->root.refcount = 2;
	SPDK_NOTICELOG("NVRocks session for '%s' has been established. root-fh=[%d=0x%lx], n_cpus=%d\n",
		vfsdev->domain, vfsdev->root.fh.len, *(uint64_t*)(vfsdev->root.fh.val), n_cpus);
	return 0;
}

int
spdk_fsdev_nvr_create(struct spdk_fsdev** fsdev, const char* name, const char* domain,
	const char* mds_addr, uint16_t mds_port, bool xattr_enabled)
{
	struct nvr_fsdev *vfsdev;
	int rc;
	struct lo_map_elem *root_elem;

	vfsdev = calloc(1, sizeof(*vfsdev));
	if (!vfsdev) {
		SPDK_ERRLOG("Cannot allocate nvr_fsdev\n");
		return -ENOMEM;
	}

	vfsdev->fsdev.name = strdup(name);
	if (!vfsdev->fsdev.name) {
		SPDK_ERRLOG("Cannot strdup fsdev name: %s\n", name);
		fsdev_nvr_free(vfsdev);
		return -ENOMEM;
	}

	vfsdev->domain = strdup(domain);
	if (!vfsdev->domain) {
		SPDK_ERRLOG("Cannot strdup domain: %s\n", domain);
		fsdev_nvr_free(vfsdev);
		return -ENOMEM;
	}

	vfsdev->mds_addr = strdup(mds_addr);
	if (!vfsdev->mds_addr) {
		SPDK_ERRLOG("Cannot strdup mds_addr: %s\n", mds_addr);
		fsdev_nvr_free(vfsdev);
		return -ENOMEM;
	}

	vfsdev->xattr_enabled = xattr_enabled;

	// Create the RDMA memory domain
	rc = spdk_memory_domain_create(&g_memory_domain, SPDK_DMA_DEVICE_TYPE_RDMA, NULL, "NVrocks-dma");

	// Initialize the NVRcoks client and setup the root inode
	vfsdev->mds_port = mds_port;
	rc = setup_clnt(vfsdev);
	if (rc) {
		SPDK_ERRLOG("Cannot setup NVRocks client: %s\n", mds_addr);
		fsdev_nvr_free(vfsdev);
		return -rc;
	}

	vfsdev->fsdev.ctxt = vfsdev;
	vfsdev->fsdev.fn_table = &nvr_fn_table;
	vfsdev->fsdev.module = &nvr_fsdev_module;

	pthread_mutex_init(&vfsdev->mutex, NULL);

	spdk_htable_init(&vfsdev->inodes);

	/* Set up the ino map like this:
	 * [0] Reserved (will not be used)
	 * [1] Root inode
	 */
	lo_map_init(&vfsdev->ino_map);
	lo_map_reserve(&vfsdev->ino_map, 0)->in_use = false;
	root_elem = lo_map_reserve(&vfsdev->ino_map, vfsdev->root.fuse_ino);
	root_elem->inode = &vfsdev->root;

	//lo_map_init(&vfsdev->dirp_map);
	lo_map_init(&vfsdev->fh_map);

	rc = spdk_fsdev_register(&vfsdev->fsdev);
	if (rc) {
		SPDK_ERRLOG("Cannot register nvr fsdev module: %d\n", rc);
		fsdev_nvr_free(vfsdev);
		return rc;
	}

	vfsdev->fsdev.opts.writeback_cache_enabled = false;
	vfsdev->fsdev.opts.max_write = DEFAULT_MAX_WRITE;

	*fsdev = &(vfsdev->fsdev);
	TAILQ_INSERT_TAIL(&g_nvr_fsdev_head, vfsdev, tailq);
	SPDK_DEBUGLOG(fsdev_nvr, "Created nvr filesystem %s (domain=%s, mds_addr=%s:%d, xattr_enabled=%d)\n",
		vfsdev->fsdev.name, vfsdev->domain, vfsdev->mds_addr, vfsdev->mds_port, vfsdev->xattr_enabled);
	return rc;
}
void
spdk_fsdev_nvr_delete(const char *name,
		      spdk_delete_nvr_fsdev_complete cb_fn, void *cb_arg)
{
	int rc;

	rc = spdk_fsdev_unregister_by_name(name, &nvr_fsdev_module, cb_fn, cb_arg);
	if (rc != 0) {
		cb_fn(cb_arg, rc);
	}

	SPDK_DEBUGLOG(fsdev_nvr, "Deleted nvr filesystem %s\n", name);
}

SPDK_LOG_REGISTER_COMPONENT(fsdev_nvr)
