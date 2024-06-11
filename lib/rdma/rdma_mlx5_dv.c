/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2020 Intel Corporation. All rights reserved.
 *   Copyright (c) 2020, 2021 Mellanox Technologies LTD. All rights reserved.
 *   Copyright (c) 2023-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include <rdma/rdma_cma.h>
#include <infiniband/mlx5dv.h>

#include "spdk/stdinc.h"
#include "spdk/string.h"
#include "spdk/likely.h"
#include "spdk/accel_module.h"

#include "spdk_internal/mlx5.h"
#include "spdk_internal/rdma.h"
#include "spdk/log.h"
#include "spdk/util.h"

struct spdk_rdma_mlx5_dv_qp {
	struct spdk_rdma_qp common;
	struct ibv_qp_ex *qpex;
	void *mkey_pool_ch[SPDK_MLX5_MKEY_POOL_FLAG_COUNT + 1];
	bool supports_accel;
};

struct rdma_mlx5_dv_accel_seq_context {
	struct spdk_mlx5_driver_io_context mlx5;
};

static int
rdma_mlx5_dv_init_qpair(struct spdk_rdma_mlx5_dv_qp *mlx5_qp)
{
	struct ibv_qp_attr qp_attr;
	int qp_attr_mask, rc;

	qp_attr.qp_state = IBV_QPS_INIT;
	rc = rdma_init_qp_attr(mlx5_qp->common.cm_id, &qp_attr, &qp_attr_mask);
	if (rc) {
		SPDK_ERRLOG("Failed to init attr IBV_QPS_INIT, errno %s (%d)\n", spdk_strerror(errno), errno);
		return rc;
	}

	rc = ibv_modify_qp(mlx5_qp->common.qp, &qp_attr, qp_attr_mask);
	if (rc) {
		SPDK_ERRLOG("ibv_modify_qp(IBV_QPS_INIT) failed, rc %d\n", rc);
		return rc;
	}

	qp_attr.qp_state = IBV_QPS_RTR;
	rc = rdma_init_qp_attr(mlx5_qp->common.cm_id, &qp_attr, &qp_attr_mask);
	if (rc) {
		SPDK_ERRLOG("Failed to init attr IBV_QPS_RTR, errno %s (%d)\n", spdk_strerror(errno), errno);
		return rc;
	}

	rc = ibv_modify_qp(mlx5_qp->common.qp, &qp_attr, qp_attr_mask);
	if (rc) {
		SPDK_ERRLOG("ibv_modify_qp(IBV_QPS_RTR) failed, rc %d\n", rc);
		return rc;
	}

	qp_attr.qp_state = IBV_QPS_RTS;
	rc = rdma_init_qp_attr(mlx5_qp->common.cm_id, &qp_attr, &qp_attr_mask);
	if (rc) {
		SPDK_ERRLOG("Failed to init attr IBV_QPS_RTR, errno %s (%d)\n", spdk_strerror(errno), errno);
		return rc;
	}

	rc = ibv_modify_qp(mlx5_qp->common.qp, &qp_attr, qp_attr_mask);
	if (rc) {
		SPDK_ERRLOG("ibv_modify_qp(IBV_QPS_RTS) failed, rc %d\n", rc);
	}

	return rc;
}

struct spdk_rdma_qp *
spdk_rdma_qp_create(struct rdma_cm_id *cm_id, struct spdk_rdma_qp_init_attr *qp_attr)
{
	assert(cm_id);
	assert(qp_attr);

	struct ibv_qp *qp;
	struct spdk_rdma_mlx5_dv_qp *mlx5_qp;
	struct ibv_qp_init_attr_ex dv_qp_attr = {
		.qp_context = qp_attr->qp_context,
		.send_cq = qp_attr->cq->cq,
		.recv_cq = qp_attr->cq->cq,
		.srq = qp_attr->srq,
		.cap = qp_attr->cap,
		.qp_type = IBV_QPT_RC,
		.comp_mask = IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_SEND_OPS_FLAGS,
		.pd = qp_attr->pd ? qp_attr->pd : cm_id->pd
	};
	const char *accel_driver;

	assert(dv_qp_attr.pd);

	mlx5_qp = calloc(1, sizeof(*mlx5_qp));
	if (!mlx5_qp) {
		SPDK_ERRLOG("qp memory allocation failed\n");
		return NULL;
	}

	if (qp_attr->stats) {
		mlx5_qp->common.stats = qp_attr->stats;
		mlx5_qp->common.shared_stats = true;
	} else {
		mlx5_qp->common.stats = calloc(1, sizeof(*mlx5_qp->common.stats));
		if (!mlx5_qp->common.stats) {
			SPDK_ERRLOG("qp statistics memory allocation failed\n");
			free(mlx5_qp);
			return NULL;
		}
	}

	qp = mlx5dv_create_qp(cm_id->verbs, &dv_qp_attr, NULL);

	if (!qp) {
		SPDK_ERRLOG("Failed to create qpair, errno %s (%d)\n", spdk_strerror(errno), errno);
		free(mlx5_qp);
		return NULL;
	}

	mlx5_qp->common.qp = qp;
	mlx5_qp->common.cm_id = cm_id;
	mlx5_qp->qpex = ibv_qp_to_qp_ex(qp);

	if (!mlx5_qp->qpex) {
		spdk_rdma_qp_destroy(&mlx5_qp->common);
		return NULL;
	}

	qp_attr->cap = dv_qp_attr.cap;

	accel_driver = spdk_accel_driver_get_name();
	if (accel_driver != NULL &&
	    strncmp(accel_driver, SPDK_MLX5_DRIVER_NAME, sizeof(SPDK_MLX5_DRIVER_NAME)) == 0) {
		mlx5_qp->mkey_pool_ch[SPDK_MLX5_MKEY_POOL_FLAG_CRYPTO] = spdk_mlx5_mkey_pool_get_channel(
					qp_attr->pd, SPDK_MLX5_MKEY_POOL_FLAG_CRYPTO);
		mlx5_qp->supports_accel = mlx5_qp->supports_accel ||
					  mlx5_qp->mkey_pool_ch[SPDK_MLX5_MKEY_POOL_FLAG_CRYPTO] != NULL;
		mlx5_qp->mkey_pool_ch[SPDK_MLX5_MKEY_POOL_FLAG_SIGNATURE] = spdk_mlx5_mkey_pool_get_channel(
					qp_attr->pd, SPDK_MLX5_MKEY_POOL_FLAG_SIGNATURE);
		mlx5_qp->supports_accel = mlx5_qp->supports_accel ||
					  mlx5_qp->mkey_pool_ch[SPDK_MLX5_MKEY_POOL_FLAG_SIGNATURE] != NULL;
		mlx5_qp->mkey_pool_ch[SPDK_MLX5_MKEY_POOL_FLAG_CRYPTO | SPDK_MLX5_MKEY_POOL_FLAG_SIGNATURE] =
			spdk_mlx5_mkey_pool_get_channel(qp_attr->pd,
							SPDK_MLX5_MKEY_POOL_FLAG_CRYPTO | SPDK_MLX5_MKEY_POOL_FLAG_SIGNATURE);
		mlx5_qp->supports_accel = mlx5_qp->supports_accel ||
					  mlx5_qp->mkey_pool_ch[SPDK_MLX5_MKEY_POOL_FLAG_CRYPTO | SPDK_MLX5_MKEY_POOL_FLAG_SIGNATURE] != NULL;
		SPDK_DEBUGLOG(rdma_prov, "mlx5 driver enabled, accel support %d\n", mlx5_qp->supports_accel);
	}

	return &mlx5_qp->common;
}

int
spdk_rdma_qp_accept(struct spdk_rdma_qp *spdk_rdma_qp, struct rdma_conn_param *conn_param)
{
	struct spdk_rdma_mlx5_dv_qp *mlx5_qp;

	assert(spdk_rdma_qp != NULL);
	assert(spdk_rdma_qp->cm_id != NULL);

	mlx5_qp = SPDK_CONTAINEROF(spdk_rdma_qp, struct spdk_rdma_mlx5_dv_qp, common);

	/* NVMEoF target must move qpair to RTS state */
	if (rdma_mlx5_dv_init_qpair(mlx5_qp) != 0) {
		SPDK_ERRLOG("Failed to initialize qpair\n");
		/* Set errno to be compliant with rdma_accept behaviour */
		errno = ECONNABORTED;
		return -1;
	}

	return rdma_accept(spdk_rdma_qp->cm_id, conn_param);
}

int
spdk_rdma_qp_complete_connect(struct spdk_rdma_qp *spdk_rdma_qp)
{
	struct spdk_rdma_mlx5_dv_qp *mlx5_qp;
	int rc;

	assert(spdk_rdma_qp);

	mlx5_qp = SPDK_CONTAINEROF(spdk_rdma_qp, struct spdk_rdma_mlx5_dv_qp, common);

	rc = rdma_mlx5_dv_init_qpair(mlx5_qp);
	if (rc) {
		SPDK_ERRLOG("Failed to initialize qpair\n");
		return rc;
	}

	rc = rdma_establish(mlx5_qp->common.cm_id);
	if (rc) {
		SPDK_ERRLOG("rdma_establish failed, errno %s (%d)\n", spdk_strerror(errno), errno);
	}

	return rc;
}

void
spdk_rdma_qp_destroy(struct spdk_rdma_qp *spdk_rdma_qp)
{
	struct spdk_rdma_mlx5_dv_qp *mlx5_qp;
	uint32_t i;
	int rc;

	assert(spdk_rdma_qp != NULL);

	mlx5_qp = SPDK_CONTAINEROF(spdk_rdma_qp, struct spdk_rdma_mlx5_dv_qp, common);

	if (spdk_rdma_qp->send_wrs.first != NULL) {
		SPDK_WARNLOG("Destroying qpair with queued Work Requests\n");
	}

	if (!mlx5_qp->common.shared_stats) {
		free(mlx5_qp->common.stats);
	}

	for (i = 0; i < SPDK_COUNTOF(mlx5_qp->mkey_pool_ch); i++) {
		if (mlx5_qp->mkey_pool_ch[i]) {
			spdk_mlx5_mkey_pool_put_channel(mlx5_qp->mkey_pool_ch[i]);
			mlx5_qp->mkey_pool_ch[i] = NULL;
		}
	}

	if (mlx5_qp->common.qp) {
		rc = ibv_destroy_qp(mlx5_qp->common.qp);
		if (rc) {
			SPDK_ERRLOG("Failed to destroy ibv qp %p, rc %d\n", mlx5_qp->common.qp, rc);
		}
	}

	free(mlx5_qp);
}

int
spdk_rdma_qp_disconnect(struct spdk_rdma_qp *spdk_rdma_qp)
{
	int rc = 0;

	assert(spdk_rdma_qp != NULL);

	if (spdk_rdma_qp->qp) {
		struct ibv_qp_attr qp_attr = {.qp_state = IBV_QPS_ERR};

		rc = ibv_modify_qp(spdk_rdma_qp->qp, &qp_attr, IBV_QP_STATE);
		if (rc) {
			SPDK_ERRLOG("Failed to modify ibv qp %p state to ERR, rc %d\n", spdk_rdma_qp->qp, rc);
			return rc;
		}
	}

	if (spdk_rdma_qp->cm_id) {
		rc = rdma_disconnect(spdk_rdma_qp->cm_id);
		if (rc) {
			SPDK_ERRLOG("rdma_disconnect failed, errno %s (%d)\n", spdk_strerror(errno), errno);
		}
	}

	return rc;
}

bool
spdk_rdma_qp_queue_send_wrs(struct spdk_rdma_qp *spdk_rdma_qp, struct ibv_send_wr *first)
{
	struct ibv_send_wr *tmp;
	struct spdk_rdma_mlx5_dv_qp *mlx5_qp;
	bool is_first;

	assert(spdk_rdma_qp);
	assert(first);

	is_first = spdk_rdma_qp->send_wrs.first == NULL;
	mlx5_qp = SPDK_CONTAINEROF(spdk_rdma_qp, struct spdk_rdma_mlx5_dv_qp, common);

	if (is_first) {
		ibv_wr_start(mlx5_qp->qpex);
		spdk_rdma_qp->send_wrs.first = first;
	} else {
		spdk_rdma_qp->send_wrs.last->next = first;
	}

	for (tmp = first; tmp != NULL; tmp = tmp->next) {
		mlx5_qp->qpex->wr_id = tmp->wr_id;
		mlx5_qp->qpex->wr_flags = tmp->send_flags;

		switch (tmp->opcode) {
		case IBV_WR_SEND:
			ibv_wr_send(mlx5_qp->qpex);
			break;
		case IBV_WR_SEND_WITH_INV:
			ibv_wr_send_inv(mlx5_qp->qpex, tmp->invalidate_rkey);
			break;
		case IBV_WR_RDMA_READ:
			ibv_wr_rdma_read(mlx5_qp->qpex, tmp->wr.rdma.rkey, tmp->wr.rdma.remote_addr);
			break;
		case IBV_WR_RDMA_WRITE:
			ibv_wr_rdma_write(mlx5_qp->qpex, tmp->wr.rdma.rkey, tmp->wr.rdma.remote_addr);
			break;
		default:
			SPDK_ERRLOG("Unexpected opcode %d\n", tmp->opcode);
			assert(0);
		}

		ibv_wr_set_sge_list(mlx5_qp->qpex, tmp->num_sge, tmp->sg_list);

		spdk_rdma_qp->send_wrs.last = tmp;
		spdk_rdma_qp->stats->send.num_submitted_wrs++;
	}

	return is_first;
}

int
spdk_rdma_qp_flush_send_wrs(struct spdk_rdma_qp *spdk_rdma_qp, struct ibv_send_wr **bad_wr)
{
	struct spdk_rdma_mlx5_dv_qp *mlx5_qp;
	int rc;

	assert(bad_wr);
	assert(spdk_rdma_qp);

	mlx5_qp = SPDK_CONTAINEROF(spdk_rdma_qp, struct spdk_rdma_mlx5_dv_qp, common);

	if (spdk_unlikely(spdk_rdma_qp->send_wrs.first == NULL)) {
		return 0;
	}

	rc = ibv_wr_complete(mlx5_qp->qpex);

	if (spdk_unlikely(rc)) {
		/* If ibv_wr_complete reports an error that means that no WRs are posted to NIC */
		*bad_wr = spdk_rdma_qp->send_wrs.first;
	}

	spdk_rdma_qp->send_wrs.first = NULL;
	spdk_rdma_qp->stats->send.doorbell_updates++;

	return rc;
}

size_t
spdk_rdma_get_io_context_size(void)
{
	return sizeof(struct rdma_mlx5_dv_accel_seq_context);
}

bool
spdk_rdma_accel_sequence_supported(struct spdk_rdma_qp *qp)
{
	struct spdk_rdma_mlx5_dv_qp *mlx5_qp;

	mlx5_qp = SPDK_CONTAINEROF(qp, struct spdk_rdma_mlx5_dv_qp, common);
	return mlx5_qp->supports_accel;
}

int
spdk_rdma_accel_sequence_finish(struct spdk_rdma_qp *qp, void *_rdma_io_ctx,
				struct spdk_accel_sequence *seq, spdk_rdma_accel_seq_cb cb_fn, void *cb_ctx)
{
	struct spdk_rdma_mlx5_dv_qp *mlx5_qp;
	struct rdma_mlx5_dv_accel_seq_context *rdma_io_ctx = _rdma_io_ctx;

	mlx5_qp = SPDK_CONTAINEROF(qp, struct spdk_rdma_mlx5_dv_qp, common);

	if (spdk_unlikely(!mlx5_qp->supports_accel)) {
		return -ENOTSUP;
	}
	rdma_io_ctx->mlx5.qp = mlx5_qp->common.qp;
	assert(rdma_io_ctx->mlx5.mkey == NULL);
	spdk_accel_sequence_set_driver_ctx(seq, &rdma_io_ctx->mlx5);

	SPDK_DEBUGLOG(rdma_prov, "accel seq %p, driver ctx %p\n", seq, &rdma_io_ctx->mlx5);
	spdk_accel_sequence_finish(seq, (spdk_accel_completion_cb)cb_fn, cb_ctx);
	qp->stats->accel_sequences_executed++;

	return 0;
}

int
spdk_rdma_accel_seq_get_translation(void *_rdma_io_ctx,
				    struct  spdk_rdma_memory_translation_ctx *translation)
{
	struct rdma_mlx5_dv_accel_seq_context *rdma_io_ctx = _rdma_io_ctx;

	if (spdk_unlikely(!rdma_io_ctx->mlx5.mkey)) {
		return -EINVAL;
	}

	/* When UMR is registered, address becomes and offset in the UMR address space */
	translation->addr = NULL;
	translation->lkey = rdma_io_ctx->mlx5.mkey->mkey;
	translation->rkey = rdma_io_ctx->mlx5.mkey->mkey;

	SPDK_DEBUGLOG(rdma_prov, "driver ctx %p, mkey %u\n", &rdma_io_ctx->mlx5,
		      rdma_io_ctx->mlx5.mkey->mkey);

	return 0;
}

int
spdk_rdma_accel_sequence_release(struct spdk_rdma_qp *qp, void *_rdma_io_ctx)
{
	struct spdk_rdma_mlx5_dv_qp *mlx5_qp;
	struct rdma_mlx5_dv_accel_seq_context *rdma_io_ctx = _rdma_io_ctx;

	mlx5_qp = SPDK_CONTAINEROF(qp, struct spdk_rdma_mlx5_dv_qp, common);
	if (spdk_unlikely(rdma_io_ctx->mlx5.mkey == NULL)) {
		/* This function might be called in error path when accel_sequence_finish failed
		 * and cb_fn of the sequence is called */
		return 0;
	}
	assert(rdma_io_ctx->mlx5.mkey->pool_flag < SPDK_MLX5_MKEY_POOL_FLAG_COUNT + 1);

	if (spdk_unlikely(mlx5_qp->mkey_pool_ch[rdma_io_ctx->mlx5.mkey->pool_flag] == NULL)) {
		SPDK_ERRLOG("Can't find chanel for mkey pool %x\n", rdma_io_ctx->mlx5.mkey->pool_flag);
		/* Should never happen */
		assert(0);
		return -EINVAL;
	}

	spdk_mlx5_mkey_pool_put_bulk(mlx5_qp->mkey_pool_ch[rdma_io_ctx->mlx5.mkey->pool_flag],
				     &rdma_io_ctx->mlx5.mkey, 1);
	rdma_io_ctx->mlx5.mkey = NULL;

	return 0;
}

struct spdk_rdma_cq *
spdk_rdma_cq_create(struct spdk_rdma_cq_init_attr *cq_attr)
{
	struct spdk_rdma_cq *rdma_cq;

	rdma_cq = calloc(1, sizeof(*rdma_cq));
	if (!rdma_cq) {
		SPDK_ERRLOG("CQ memory allocation failed\n");
		return NULL;
	}

	rdma_cq->cq = ibv_create_cq(cq_attr->pd->context, cq_attr->cqe, cq_attr->cq_context,
				    cq_attr->comp_channel,
				    cq_attr->comp_vector);
	if (!rdma_cq->cq) {
		SPDK_ERRLOG("Unable to create completion queue: errno %d: %s\n", errno, spdk_strerror(errno));
		free(rdma_cq);
		return NULL;
	}

	return rdma_cq;
}

void
spdk_rdma_cq_destroy(struct spdk_rdma_cq *rdma_cq)
{
	assert(rdma_cq);

	ibv_destroy_cq(rdma_cq->cq);
	free(rdma_cq);
}

int
spdk_rdma_cq_resize(struct spdk_rdma_cq *rdma_cq, int cqe)
{
	assert(rdma_cq);

	return ibv_resize_cq(rdma_cq->cq, cqe);
}

int
spdk_rdma_cq_poll(struct spdk_rdma_cq *rdma_cq, int num_entries, struct ibv_wc *wc)
{
	assert(rdma_cq);
	assert(wc);

	return ibv_poll_cq(rdma_cq->cq, num_entries, wc);
}
