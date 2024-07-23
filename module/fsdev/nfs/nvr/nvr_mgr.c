/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */
#include "spdk/util.h"
#include "spdk/log.h"
#include "spdk/thread.h"
#include "spdk/bdev_zone.h"
#include "spdk/fsdev_module.h"
#include "nvr_mgr.h"

#define DEFAULT_BDEV "Malloc0"
#define MEMORY_DOMAIN_NAME "nvrocks"
#define OP_STATUS_ASYNC INT_MIN
#define WREQ_QDEPTH	64

/** IO request type */
enum nvr_io_req_type {
	NVR_MGR_IO_TYPE_ZONE,
	NVR_MGR_IO_TYPE_READ,
	NVR_MGR_IO_TYPE_WRITE,
};

struct nvr_io_req {
	enum nvr_io_req_type type;
	struct spdk_nvr_bdev_ctxt* bdev_ctxt;
	struct spdk_bdev_io_wait_entry bdev_io_wait;
	fsdev_nvr_done_cb clb;
	struct spdk_fsdev_io* fsdev_io;
};

struct spdk_nvr_bdev_ctxt {
	struct spdk_nvr_mgr* mgr;
	struct spdk_bdev* bdev;
	struct spdk_bdev_desc* bdev_desc;
	struct spdk_io_channel* bdev_io_channel;
	uint32_t blksize;
	uint32_t blk_shift_cnt;
	bool rdma_zcopy_enabled;
	struct nvr_io_req* reqs;
	uint32_t reqs_idx;
	uint32_t reqs_pending;
};

struct spdk_nvr_mgr {
	struct spdk_nvr_bdev_ctxt** bdevs;
	uint32_t bdevs_cnt;
};

static struct spdk_nvr_bdev_ctxt* nvr_bdev_open(const char* name);
static int nvr_bdev_reset_zone(void* arg);
static bool nvr_mgr_is_rdma_zcopy_enabled(struct spdk_bdev* bdev, const char* name);
static void nvr_mgr_read_wait_cb(void* arg);
static void nvr_mgr_write_wait_cb(void* arg);
static void nvr_mgr_zone_wait_cb(void* arg);

static void
nvr_bdev_event_cb(enum spdk_bdev_event_type type, struct spdk_bdev* bdev,
	void* event_ctx)
{
	SPDK_NOTICELOG("Unsupported bdev event: type %d\n", type);
}

static void
nvr_mgr_zone_wait_cb(void* arg)
{
	struct nvr_io_req* req = arg;
	req->bdev_ctxt->reqs_pending--;

	assert(req->type == NVR_MGR_IO_TYPE_ZONE);
	nvr_bdev_reset_zone(req->bdev_ctxt);
}

static void
nvr_bdev_reset_zone_cb(struct spdk_bdev_io* bdev_io, bool success, void* cb_arg)
{
	/* Complete the I/O */
	spdk_bdev_free_io(bdev_io);

	if (!success) {
		SPDK_ERRLOG("bdev io reset zone error: %d\n", EIO);
		// TODO
	}
}

static int
nvr_bdev_reset_zone(void* arg)
{
	struct spdk_nvr_bdev_ctxt* bdev_ctxt = arg;
	int rc;

	rc = spdk_bdev_zone_management(bdev_ctxt->bdev_desc, bdev_ctxt->bdev_io_channel,
		0, SPDK_BDEV_ZONE_RESET, nvr_bdev_reset_zone_cb, bdev_ctxt);

	if (rc == -ENOMEM) {
		SPDK_NOTICELOG("Queueing io for bdev %s\n", spdk_bdev_get_name(bdev_ctxt->bdev));
		/* In case we cannot perform I/O now, queue I/O */
		if (bdev_ctxt->reqs_pending >= WREQ_QDEPTH) {
			SPDK_ERRLOG("error while resetting zone: %d\n", rc);
			return rc;
		}
		struct nvr_io_req* req = &bdev_ctxt->reqs[bdev_ctxt->reqs_idx];
		req->type = NVR_MGR_IO_TYPE_ZONE;
		req->bdev_ctxt = bdev_ctxt;
		req->bdev_io_wait.bdev = bdev_ctxt->bdev;
		req->bdev_io_wait.cb_fn = nvr_mgr_zone_wait_cb;
		req->bdev_io_wait.cb_arg = req;
		if (spdk_bdev_queue_io_wait(bdev_ctxt->bdev, bdev_ctxt->bdev_io_channel,
			&req->bdev_io_wait)) {
			SPDK_ERRLOG("error while resetting zone: %d\n", rc);
			return rc;
		}
		if (++bdev_ctxt->reqs_idx >= WREQ_QDEPTH) {
			bdev_ctxt->reqs_idx = 0;
		}
		bdev_ctxt->reqs_pending++;
	}
	else if (rc) {
		SPDK_ERRLOG("error while resetting zone: %d\n", rc);
	}

	return rc;
}

static bool
nvr_mgr_is_rdma_zcopy_enabled(struct spdk_bdev* bdev, const char* name) {
	bool rdma_zcopy_enabled = false;
	int nds, nds_tmp;
	struct spdk_memory_domain** bdev_domains = NULL;

	// Check whether memory domains are set
	nds = spdk_bdev_get_memory_domains(bdev, NULL, 0);
	if (nds < 0) {
		SPDK_ERRLOG("failed to get bdev memory domains count for bdev %s\n", name);
		return false;
	}

	if (nds == 0) { return false; }

	bdev_domains = calloc((size_t)nds, sizeof(struct spdk_memory_domain*));
	if (bdev_domains) {
		SPDK_ERRLOG("cannot alloc memory domains array of %d for bdev %s\n", nds, name);
		return false;
	}
	nds_tmp = spdk_bdev_get_memory_domains(bdev, bdev_domains, nds);
	if (nds_tmp != nds) {
		SPDK_ERRLOG("got unexpected number of memory domains for bdev %s (cnt=%d:%d)\n", name, nds_tmp, nds);
		free(bdev_domains);
		return false;
	}

	for (int i = 0; i < nds; i++) {
		if (spdk_memory_domain_get_dma_device_type(bdev_domains[i]) == SPDK_DMA_DEVICE_TYPE_RDMA) {
			rdma_zcopy_enabled = true;
			break;
		}
	}

	free(bdev_domains);
	return rdma_zcopy_enabled;

}

static struct spdk_nvr_bdev_ctxt *
nvr_bdev_open(const char* name)
{
	struct spdk_nvr_bdev_ctxt* bdev_ctxt = NULL;

	bdev_ctxt = calloc(1, sizeof(*bdev_ctxt));
	if (!bdev_ctxt) {
		SPDK_ERRLOG("cannot alloc bdev_ctxt of %zu bytes\n", sizeof(*bdev_ctxt));
		return NULL;
	}

	int rc = spdk_bdev_open_ext(name, true, nvr_bdev_event_cb, NULL, &bdev_ctxt->bdev_desc);
	if (rc) {
		SPDK_ERRLOG("cannot open bdev: %s\n", name);
		goto out_err;
	}

	/* A bdev pointer is valid while the bdev is opened. */
	bdev_ctxt->bdev = spdk_bdev_desc_get_bdev(bdev_ctxt->bdev_desc);
	bdev_ctxt->rdma_zcopy_enabled = nvr_mgr_is_rdma_zcopy_enabled(bdev_ctxt->bdev, name);

	/* Allocate queue for waiting IO requests */
	bdev_ctxt->reqs = calloc(WREQ_QDEPTH, sizeof(*bdev_ctxt->reqs));
	if (!bdev_ctxt->reqs) {
		SPDK_ERRLOG("cannot alloc reqs array of %d for bdev %s\n", WREQ_QDEPTH, name);
		goto out_err;
	}

	for (int i = 0; i < WREQ_QDEPTH; i++) {
		bdev_ctxt->reqs[i].bdev_ctxt = bdev_ctxt;
	}

	/* Open I/O channel */
	bdev_ctxt->bdev_io_channel = spdk_bdev_get_io_channel(bdev_ctxt->bdev_desc);
	if (bdev_ctxt->bdev_io_channel == NULL) {
		SPDK_ERRLOG("cannot create bdev I/O channel for bdev %s!!\n", name);
		goto out_err;
	}

	bdev_ctxt->blksize = spdk_bdev_get_block_size(bdev_ctxt->bdev) *
		spdk_bdev_get_write_unit_size(bdev_ctxt->bdev);
	bdev_ctxt->blk_shift_cnt = spdk_u32log2(bdev_ctxt->blksize);

	if (spdk_bdev_is_zoned(bdev_ctxt->bdev)) {
		if (nvr_bdev_reset_zone(bdev_ctxt)) {
			SPDK_ERRLOG("cannot reset zone for bdev %s!!\n", name);
			goto out_err;
		}
	}

	SPDK_NOTICELOG("IO channel for bdev %s was created (block_size=%d, shift_cnt=%d, zcopy=%d)\n",
		name, bdev_ctxt->blksize, bdev_ctxt->blk_shift_cnt, bdev_ctxt->rdma_zcopy_enabled);

	return bdev_ctxt;

out_err:
	if (bdev_ctxt) {
		if (bdev_ctxt->bdev_desc) { spdk_bdev_close(bdev_ctxt->bdev_desc); }
		if (bdev_ctxt->reqs) { free(bdev_ctxt->reqs); }
		free(bdev_ctxt);
	}
	return NULL;
}

struct spdk_nvr_mgr *
spdk_nvr_mgr_create(void)
{
	struct spdk_nvr_mgr *mgr;
	struct spdk_bdev* bdev;
	struct spdk_nvr_bdev_ctxt* bdev_ctxt;
	int count;

	mgr = calloc(1, sizeof(*mgr));
	if (!mgr) {
		SPDK_ERRLOG("cannot alloc mgr of %zu bytes\n", sizeof(*mgr));
		return NULL;
	}

	// Find out the number of registered bdev
	for (count = 0, bdev = spdk_bdev_first_leaf(); bdev != NULL; count++, bdev = spdk_bdev_next_leaf(bdev));

	mgr->bdevs_cnt = 0;
	mgr->bdevs = calloc(count, sizeof(mgr->bdevs));
	if (!mgr->bdevs) {
		SPDK_ERRLOG("cannot alloc bdevs array of %" PRIu32 "\n", count);
		free(mgr);
		return NULL;
	}

	// Create IO channel for each registered bdev
	for (bdev = spdk_bdev_first_leaf(); bdev != NULL; bdev=spdk_bdev_next_leaf(bdev)) {
		if ((bdev_ctxt = nvr_bdev_open(spdk_bdev_get_name(bdev))) != NULL) {
			bdev_ctxt->mgr = mgr;
			mgr->bdevs[mgr->bdevs_cnt++] = bdev_ctxt;
		}
	}

	if (mgr->bdevs_cnt == 0) {
		SPDK_ERRLOG("there are no available bdevs\n");
		free(mgr);
		return NULL;
	}

	return mgr;
}

static void
nvr_mgr_read_wait_cb(void* arg)
{
	struct nvr_io_req* req = arg;
	req->bdev_ctxt->reqs_pending--;

	assert(req->type == NVR_MGR_IO_TYPE_READ);
	spdk_nvr_mgr_read(req->bdev_ctxt->mgr, spdk_bdev_get_name(req->bdev_ctxt->bdev), req->clb, req->fsdev_io);
}

int
spdk_nvr_mgr_read(struct spdk_nvr_mgr* mgr, const char *name,
	fsdev_nvr_done_cb clb, struct spdk_fsdev_io* fsdev_io)
{
	int rc;
	size_t size = fsdev_io->u_in.read.size;
	uint64_t offs = fsdev_io->u_in.read.offs;
	struct iovec* outvec = fsdev_io->u_in.read.iov;
	uint32_t outcnt = fsdev_io->u_in.read.iovcnt;
	struct spdk_bdev_ext_io_opts* opts = NULL;
	uint64_t offs_blocks, num_blocks;

	// TODO: Find out the context from the name
	struct spdk_nvr_bdev_ctxt* bdev_ctxt = mgr->bdevs[0];

	// Make sure the size is divisible by the block size
	// TODO: Need to handle unaligned blocks properly (read+Modify+write)
	if (size % bdev_ctxt->blksize > 0) { size += bdev_ctxt->blksize; }
	offs_blocks = offs >> bdev_ctxt->blk_shift_cnt;
	num_blocks = size >> bdev_ctxt->blk_shift_cnt;

	if (bdev_ctxt->rdma_zcopy_enabled && fsdev_io->u_in.read.opts && fsdev_io->u_in.read.opts->memory_domain) {
		opts = (struct spdk_bdev_ext_io_opts *)fsdev_io->u_in.read.opts;
	}
	rc = spdk_bdev_readv_blocks_ext(bdev_ctxt->bdev_desc, bdev_ctxt->bdev_io_channel,
		outvec, outcnt, offs_blocks, num_blocks, clb, fsdev_io, opts);

	if (rc == -ENOMEM) {
		SPDK_NOTICELOG("Queueing io for bdev %s\n", name);
		/* In case we cannot perform I/O now, queue I/O */
		if (bdev_ctxt->reqs_pending >= WREQ_QDEPTH) {
			return rc;
		}
		struct nvr_io_req *req = &bdev_ctxt->reqs[bdev_ctxt->reqs_idx];
		req->type = NVR_MGR_IO_TYPE_READ;
		req->bdev_ctxt = bdev_ctxt;
		req->bdev_io_wait.bdev = bdev_ctxt->bdev;
		req->bdev_io_wait.cb_fn = nvr_mgr_read_wait_cb;
		req->bdev_io_wait.cb_arg = req;
		req->clb = clb;
		req->fsdev_io = fsdev_io;
		if (spdk_bdev_queue_io_wait(bdev_ctxt->bdev, bdev_ctxt->bdev_io_channel,
			&req->bdev_io_wait)) {
			return rc;
		}
		if (++bdev_ctxt->reqs_idx >= WREQ_QDEPTH) {
			bdev_ctxt->reqs_idx = 0;
		}
		bdev_ctxt->reqs_pending++;
	}
	else if (rc) {
		SPDK_ERRLOG("error while reading from bdev %s (offs=%" PRIu64 ", size=%" PRIu64 ", iovcnt = %d). err = % d\n",
			name, offs, size, outcnt, rc);
		return rc;
	}

	return OP_STATUS_ASYNC;
}

static void
nvr_mgr_write_wait_cb(void* arg)
{
	struct nvr_io_req* req = arg;
	req->bdev_ctxt->reqs_pending--;

	assert(req->type == NVR_MGR_IO_TYPE_WRITE);
	spdk_nvr_mgr_write(req->bdev_ctxt->mgr, spdk_bdev_get_name(req->bdev_ctxt->bdev), req->clb, req->fsdev_io);
}

int
spdk_nvr_mgr_write(struct spdk_nvr_mgr* mgr, const char *name,
	fsdev_nvr_done_cb clb, struct spdk_fsdev_io* fsdev_io)
{
	int rc;
	size_t size = fsdev_io->u_in.write.size;
	uint64_t offs = fsdev_io->u_in.write.offs;
	const struct iovec* invec = fsdev_io->u_in.write.iov;
	uint32_t incnt = fsdev_io->u_in.write.iovcnt;
	struct spdk_bdev_ext_io_opts* opts = NULL;
	uint64_t offs_blocks, num_blocks;

	// TODO: Find out the context from the name
	struct spdk_nvr_bdev_ctxt* bdev_ctxt = mgr->bdevs[0];

	// Make sure the size is divisible by the block size
	// TODO: Need to handle unaligned blocks properly (read+Modify+write)
	if (size % bdev_ctxt->blksize > 0) { size += bdev_ctxt->blksize; }
	offs_blocks = offs >> bdev_ctxt->blk_shift_cnt;
	num_blocks = size >> bdev_ctxt->blk_shift_cnt;

	if (bdev_ctxt->rdma_zcopy_enabled && fsdev_io->u_in.write.opts && fsdev_io->u_in.write.opts->memory_domain) {
		opts = (struct spdk_bdev_ext_io_opts*)fsdev_io->u_in.write.opts;
	}
	rc = spdk_bdev_writev_blocks_ext(bdev_ctxt->bdev_desc, bdev_ctxt->bdev_io_channel,
		(struct iovec*)invec, incnt, offs_blocks, num_blocks, clb, fsdev_io, opts);

	if (rc == -ENOMEM) {
		/* In case we cannot perform I/O now, queue I/O */
		if (bdev_ctxt->reqs_pending >= WREQ_QDEPTH) {
			return rc;
		}
		struct nvr_io_req *req = &bdev_ctxt->reqs[bdev_ctxt->reqs_idx];
		req->type = NVR_MGR_IO_TYPE_WRITE;
		req->bdev_ctxt = bdev_ctxt;
		req->bdev_io_wait.bdev = bdev_ctxt->bdev;
		req->bdev_io_wait.cb_fn = nvr_mgr_write_wait_cb;
		req->bdev_io_wait.cb_arg = req;
		req->clb = clb;
		req->fsdev_io = fsdev_io;
		if (spdk_bdev_queue_io_wait(bdev_ctxt->bdev, bdev_ctxt->bdev_io_channel,
			&req->bdev_io_wait)) {
			return rc;
		}
		if (++bdev_ctxt->reqs_idx >= WREQ_QDEPTH) {
			bdev_ctxt->reqs_idx = 0;
		}
		bdev_ctxt->reqs_pending++;
	}
	else if (rc) {
		SPDK_ERRLOG("error while writing to bdev %s (offs=%" PRIu64 ", size=%" PRIu64 ", iovcnt=%d). err=%d\n",
			name, offs, size, incnt, rc);
		return rc;
	}

	return OP_STATUS_ASYNC;
}

void
spdk_nvr_mgr_delete(struct spdk_nvr_mgr *mgr)
{
	for (uint32_t i = 0; i < mgr->bdevs_cnt; i++) {
		spdk_put_io_channel(mgr->bdevs[i]->bdev_io_channel);
		spdk_bdev_close(mgr->bdevs[i]->bdev_desc);
		if (mgr->bdevs[i]->reqs) {
			free(mgr->bdevs[i]->reqs);
		}
	}
	free(mgr->bdevs);
	free(mgr);
}

SPDK_LOG_REGISTER_COMPONENT(spdk_nvr_mgr_io)
