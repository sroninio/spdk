/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

/** \file
 * Operations on nfs filesystem device
 */

#ifndef SPDK_FSDEV_NFS_H
#define SPDK_FSDEV_NFS_H

typedef void (*APP_CB)(void *, int);

struct nfs_fsdev *
nfs_fsdev_alloc_and_init(void);

void
submit(struct nfs_fsdev *fsdev, char * fuse_header, char * fuse_in, char * fuse_out, APP_CB app_cb, void *app_ctxt);

void
progress(struct nfs_fsdev * fsdev);

#endif /* SPDK_FSDEV_NFS_H */
