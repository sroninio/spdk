/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

/** \file
 * Operations on NVRocks filesystem device
 */

#ifndef SPDK_FSDEV_NVR_H
#define SPDK_FSDEV_NVR_H

#include "spdk/stdinc.h"
#include "spdk/fsdev_module.h"

typedef void (*spdk_delete_nvr_fsdev_complete)(void *cb_arg, int fsdeverrno);

int spdk_fsdev_nvr_create(struct spdk_fsdev** fsdev, const char* name, const char* domain,
	const char* mds_addr, uint16_t mds_port, bool xattr_enabled);
void spdk_fsdev_nvr_delete(const char *name, spdk_delete_nvr_fsdev_complete cb_fn, void *cb_arg);

#endif /* SPDK_FSDEV_NVR_H */