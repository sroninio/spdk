/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

/** \file
 * Vector SPDK bdevs
 */

#ifndef SPDK_NVR_MGR_H
#define SPDK_NVR_MGR_H

#include "spdk/stdinc.h"
#include "spdk/fsdev_module.h"
#include "spdk/bdev.h"

struct spdk_nvr_mgr;
struct spdk_nvr_bdev_ctxt;

typedef void (*fsdev_nvr_done_cb)(struct spdk_bdev_io* bdev_io,
	bool success, void* cb_arg);

struct spdk_nvr_mgr *spdk_nvr_mgr_create(void);
int spdk_nvr_mgr_read(struct spdk_nvr_mgr* mgr, const char* name,
	fsdev_nvr_done_cb clb, struct spdk_fsdev_io* fsdev_io);
int spdk_nvr_mgr_write(struct spdk_nvr_mgr* mgr, const char*name,
	fsdev_nvr_done_cb clb, struct spdk_fsdev_io* fsdev_io);
void spdk_nvr_mgr_delete(struct spdk_nvr_mgr *mgr);

#endif /* SPDK_NVR_MGR_H */
