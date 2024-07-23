/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

/** \file
 * Operations on nfs filesystem device
 */

#ifndef SPDK_FSDEV_NFS_H
#define SPDK_FSDEV_NFS_H

#include "spdk/stdinc.h"
#include "spdk/fsdev_module.h"

enum spdk_nfs_bool_param {
	SPDK_NFS_UNDEFINED = -1,
	SPDK_NFS_TRUE,
	SPDK_NFS_FALSE,
};

#define SPDK_NFS_MAX_WRITE_UNDEFINED 0

typedef void (*spdk_delete_nfs_fsdev_complete)(void *cb_arg, int fsdeverrno);

int spdk_fsdev_nfs_create(struct spdk_fsdev **fsdev, const char *name);
void spdk_fsdev_nfs_delete(const char *name, spdk_delete_nfs_fsdev_complete cb_fn, void *cb_arg);

#endif /* SPDK_FSDEV_NFS_H */
