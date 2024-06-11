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
	struct spdk_mlx5_qp *mlx5_qp;
	int send_err;
	int recv_err;
	void *mkey_pool_ch[SPDK_MLX5_MKEY_POOL_FLAG_COUNT + 1];
	bool supports_accel;
};

struct rdma_mlx5_dv_accel_seq_context {
	struct spdk_mlx5_driver_io_context mlx5;
};

struct mlx5_dv_cq {
	struct spdk_rdma_cq rdma_cq;
	struct spdk_mlx5_cq *mlx5_cq;
};

struct mlx5_dv_srq {
	struct spdk_rdma_srq rdma_srq;
	struct spdk_mlx5_srq *mlx5_srq;
	int recv_err;
};

struct spdk_rdma_qp *
spdk_rdma_qp_create(struct rdma_cm_id *cm_id, struct spdk_rdma_qp_init_attr *qp_attr)
{
	assert(cm_id);
	assert(qp_attr);

	struct spdk_rdma_mlx5_dv_qp *dv_qp;
	struct mlx5_dv_srq *dv_srq;
	struct spdk_mlx5_qp_attr mlx5_qp_attr = {
		.cap = qp_attr->cap,
		.qp_context = qp_attr->qp_context
	};
	struct mlx5_dv_cq *dv_cq = SPDK_CONTAINEROF(qp_attr->cq, struct mlx5_dv_cq, rdma_cq);
	struct ibv_pd *pd = qp_attr->pd ? qp_attr->pd : cm_id->pd;
	const char *accel_driver;
	int rc;

	assert(pd);

	dv_qp = calloc(1, sizeof(*dv_qp));
	if (!dv_qp) {
		SPDK_ERRLOG("qp memory allocation failed\n");
		return NULL;
	}

	if (qp_attr->stats) {
		dv_qp->common.stats = qp_attr->stats;
		dv_qp->common.shared_stats = true;
	} else {
		dv_qp->common.stats = calloc(1, sizeof(*dv_qp->common.stats));
		if (!dv_qp->common.stats) {
			SPDK_ERRLOG("qp statistics memory allocation failed\n");
			free(dv_qp);
			return NULL;
		}
	}

	if (qp_attr->srq) {
		dv_srq = SPDK_CONTAINEROF(qp_attr->srq, struct mlx5_dv_srq, rdma_srq);
		mlx5_qp_attr.srq = dv_srq->mlx5_srq;
	}

	rc = spdk_mlx5_qp_create(pd, dv_cq->mlx5_cq, &mlx5_qp_attr, &dv_qp->mlx5_qp);
	if (rc) {
		SPDK_ERRLOG("Failed to create qpair, rc %d\n", rc);
		free(dv_qp);
		return NULL;
	}

	dv_qp->common.qp = dv_qp->mlx5_qp->verbs_qp;
	dv_qp->common.cm_id = cm_id;

	qp_attr->cap = mlx5_qp_attr.cap;

	accel_driver = spdk_accel_driver_get_name();
	if (accel_driver != NULL &&
	    strncmp(accel_driver, SPDK_MLX5_DRIVER_NAME, sizeof(SPDK_MLX5_DRIVER_NAME)) == 0) {
		dv_qp->mkey_pool_ch[SPDK_MLX5_MKEY_POOL_FLAG_CRYPTO] = spdk_mlx5_mkey_pool_get_channel(
					qp_attr->pd, SPDK_MLX5_MKEY_POOL_FLAG_CRYPTO);
		dv_qp->supports_accel = dv_qp->supports_accel ||
					dv_qp->mkey_pool_ch[SPDK_MLX5_MKEY_POOL_FLAG_CRYPTO] != NULL;
		dv_qp->mkey_pool_ch[SPDK_MLX5_MKEY_POOL_FLAG_SIGNATURE] = spdk_mlx5_mkey_pool_get_channel(
					qp_attr->pd, SPDK_MLX5_MKEY_POOL_FLAG_SIGNATURE);
		dv_qp->supports_accel = dv_qp->supports_accel ||
					dv_qp->mkey_pool_ch[SPDK_MLX5_MKEY_POOL_FLAG_SIGNATURE] != NULL;
		dv_qp->mkey_pool_ch[SPDK_MLX5_MKEY_POOL_FLAG_CRYPTO | SPDK_MLX5_MKEY_POOL_FLAG_SIGNATURE] =
			spdk_mlx5_mkey_pool_get_channel(qp_attr->pd,
							SPDK_MLX5_MKEY_POOL_FLAG_CRYPTO | SPDK_MLX5_MKEY_POOL_FLAG_SIGNATURE);
		dv_qp->supports_accel = dv_qp->supports_accel ||
					dv_qp->mkey_pool_ch[SPDK_MLX5_MKEY_POOL_FLAG_CRYPTO | SPDK_MLX5_MKEY_POOL_FLAG_SIGNATURE] != NULL;
		SPDK_DEBUGLOG(rdma_mlx5_dv, "mlx5 driver enabled, accel support %d\n", dv_qp->supports_accel);
	}

	return &dv_qp->common;
}

int
spdk_rdma_qp_accept(struct spdk_rdma_qp *spdk_rdma_qp, struct rdma_conn_param *conn_param)
{
	struct spdk_rdma_mlx5_dv_qp *dv_qp;

	assert(spdk_rdma_qp != NULL);
	assert(spdk_rdma_qp->cm_id != NULL);

	dv_qp = SPDK_CONTAINEROF(spdk_rdma_qp, struct spdk_rdma_mlx5_dv_qp, common);

	/* NVMEoF target must move qpair to RTS state */
	if (spdk_mlx5_qp_connect_cm(dv_qp->mlx5_qp, spdk_rdma_qp->cm_id) != 0) {
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
	struct spdk_rdma_mlx5_dv_qp *dv_qp;
	int rc;

	assert(spdk_rdma_qp);

	dv_qp = SPDK_CONTAINEROF(spdk_rdma_qp, struct spdk_rdma_mlx5_dv_qp, common);

	rc = spdk_mlx5_qp_connect_cm(dv_qp->mlx5_qp, spdk_rdma_qp->cm_id);
	if (rc) {
		SPDK_ERRLOG("Failed to initialize qpair\n");
		return rc;
	}

	rc = rdma_establish(dv_qp->common.cm_id);
	if (rc) {
		SPDK_ERRLOG("rdma_establish failed, errno %s (%d)\n", spdk_strerror(errno), errno);
	}

	return rc;
}

void
spdk_rdma_qp_destroy(struct spdk_rdma_qp *spdk_rdma_qp)
{
	struct spdk_rdma_mlx5_dv_qp *dv_qp;
	uint32_t i;

	assert(spdk_rdma_qp != NULL);

	dv_qp = SPDK_CONTAINEROF(spdk_rdma_qp, struct spdk_rdma_mlx5_dv_qp, common);

	if (spdk_rdma_qp->send_wrs.first != NULL) {
		SPDK_WARNLOG("Destroying qpair with queued Work Requests\n");
	}

	if (!dv_qp->common.shared_stats) {
		free(dv_qp->common.stats);
	}

	for (i = 0; i < SPDK_COUNTOF(dv_qp->mkey_pool_ch); i++) {
		if (dv_qp->mkey_pool_ch[i]) {
			spdk_mlx5_mkey_pool_put_channel(dv_qp->mkey_pool_ch[i]);
			dv_qp->mkey_pool_ch[i] = NULL;
		}
	}

	if (dv_qp->mlx5_qp) {
		spdk_mlx5_qp_destroy(dv_qp->mlx5_qp);
	}

	free(dv_qp);
}

int
spdk_rdma_qp_disconnect(struct spdk_rdma_qp *spdk_rdma_qp)
{
	struct spdk_rdma_mlx5_dv_qp *dv_qp;
	int rc = 0;

	assert(spdk_rdma_qp != NULL);
	dv_qp = SPDK_CONTAINEROF(spdk_rdma_qp, struct spdk_rdma_mlx5_dv_qp, common);
	if (dv_qp->mlx5_qp) {
		struct ibv_qp_attr qp_attr = {.qp_state = IBV_QPS_ERR};

		rc = spdk_mlx5_qp_modify(dv_qp->mlx5_qp, &qp_attr, IBV_QP_STATE);
		if (rc) {
			SPDK_ERRLOG("Failed to modify qp %p state to ERR, rc %d\n", dv_qp->mlx5_qp, rc);
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

static inline uint32_t
rdma_send_flags_to_mlx5(unsigned int send_flags)
{
	uint32_t mlx5_flags = 0;

	assert((send_flags & ~(IBV_SEND_FENCE | IBV_SEND_SIGNALED | IBV_SEND_SOLICITED)) == 0);

	if (send_flags & IBV_SEND_FENCE) {
		mlx5_flags |= SPDK_MLX5_WQE_CTRL_FENCE;
	}
	if (send_flags & IBV_SEND_SIGNALED) {
		mlx5_flags |= SPDK_MLX5_WQE_CTRL_CE_CQ_UPDATE;
	}
	if (send_flags & IBV_SEND_SOLICITED) {
		mlx5_flags |= SPDK_MLX5_WQE_CTRL_SOLICITED;
	}

	return mlx5_flags;
}

static inline int
rdma_qp_queue_send_wr(struct spdk_mlx5_qp *mlx5_qp, struct ibv_send_wr *wr)
{
	int rc;
	uint32_t flags = rdma_send_flags_to_mlx5(wr->send_flags);

	switch (wr->opcode) {
	case IBV_WR_SEND:
		rc = spdk_mlx5_qp_send(mlx5_qp, wr->sg_list, wr->num_sge, wr->wr_id, flags);
		break;
	case IBV_WR_SEND_WITH_INV:
		rc = spdk_mlx5_qp_send_inv(mlx5_qp, wr->sg_list, wr->num_sge, wr->invalidate_rkey,
					   wr->wr_id, flags);
		break;
	case IBV_WR_RDMA_READ:
		rc = spdk_mlx5_qp_rdma_read(mlx5_qp, wr->sg_list, wr->num_sge, wr->wr.rdma.remote_addr,
					    wr->wr.rdma.rkey, wr->wr_id, flags);
		break;
	case IBV_WR_RDMA_WRITE:
		rc = spdk_mlx5_qp_rdma_write(mlx5_qp, wr->sg_list, wr->num_sge, wr->wr.rdma.remote_addr,
					     wr->wr.rdma.rkey, wr->wr_id, flags);
		break;
	default:
		SPDK_ERRLOG("Unexpected opcode %d\n", wr->opcode);
		rc = -EINVAL;
		assert(0);
	}

	return rc;
}

bool
spdk_rdma_qp_queue_send_wrs(struct spdk_rdma_qp *spdk_rdma_qp, struct ibv_send_wr *first)
{
	struct ibv_send_wr *tmp;
	struct spdk_rdma_mlx5_dv_qp *dv_qp;
	bool is_first;

	assert(spdk_rdma_qp);
	assert(first);

	is_first = spdk_rdma_qp->send_wrs.first == NULL;
	dv_qp = SPDK_CONTAINEROF(spdk_rdma_qp, struct spdk_rdma_mlx5_dv_qp, common);

	if (is_first) {
		spdk_rdma_qp->send_wrs.first = first;
	} else {
		spdk_rdma_qp->send_wrs.last->next = first;
	}

	for (tmp = first; tmp != NULL; tmp = tmp->next) {

		if (spdk_likely(!dv_qp->send_err)) {
			dv_qp->send_err = rdma_qp_queue_send_wr(dv_qp->mlx5_qp, tmp);
		}

		spdk_rdma_qp->send_wrs.last = tmp;
		spdk_rdma_qp->stats->send.num_submitted_wrs++;
	}

	return is_first;
}

int
spdk_rdma_qp_flush_send_wrs(struct spdk_rdma_qp *spdk_rdma_qp, struct ibv_send_wr **bad_wr)
{
	struct spdk_rdma_mlx5_dv_qp *dv_qp;

	assert(bad_wr);
	assert(spdk_rdma_qp);


	if (spdk_unlikely(spdk_rdma_qp->send_wrs.first == NULL)) {
		return 0;
	}

	dv_qp = SPDK_CONTAINEROF(spdk_rdma_qp, struct spdk_rdma_mlx5_dv_qp, common);
	if (spdk_unlikely(dv_qp->send_err)) {
		/* If send_err is not zero that means that no WRs are posted to NIC */
		*bad_wr = spdk_rdma_qp->send_wrs.first;
	} else {
		spdk_mlx5_qp_complete_send(dv_qp->mlx5_qp);
		spdk_rdma_qp->stats->send.doorbell_updates++;
	}
	spdk_rdma_qp->send_wrs.first = NULL;

	return dv_qp->send_err;
}

struct spdk_rdma_srq *
spdk_rdma_srq_create(struct spdk_rdma_srq_init_attr *init_attr)
{
	assert(init_attr);
	assert(init_attr->pd);

	struct mlx5_dv_srq *dv_srq;
	struct spdk_rdma_srq *rdma_srq;
	int rc;

	dv_srq = calloc(1, sizeof(*dv_srq));
	if (!dv_srq) {
		SPDK_ERRLOG("Can't allocate memory for SRQ handle\n");
		return NULL;
	}

	rdma_srq = &dv_srq->rdma_srq;
	if (init_attr->stats) {
		rdma_srq->stats = init_attr->stats;
		rdma_srq->shared_stats = true;
	} else {
		rdma_srq->stats = calloc(1, sizeof(*rdma_srq->stats));
		if (!rdma_srq->stats) {
			SPDK_ERRLOG("SRQ statistics memory allocation failed");
			goto err_free_srq;
		}
	}

	rc = spdk_mlx5_srq_create(init_attr->pd, &init_attr->srq_init_attr, &dv_srq->mlx5_srq);
	if (rc) {
		SPDK_ERRLOG("Unable to create SRQ, rc %d (%s)\n", rc, spdk_strerror(rc));
		goto err_free_stats;
	}

	return rdma_srq;

err_free_stats:
	if (!rdma_srq->shared_stats) {
		free(rdma_srq->stats);
	}
err_free_srq:
	free(dv_srq);

	return NULL;
}

int
spdk_rdma_srq_destroy(struct spdk_rdma_srq *rdma_srq)
{
	assert(rdma_srq);

	struct mlx5_dv_srq *dv_srq = SPDK_CONTAINEROF(rdma_srq, struct mlx5_dv_srq, rdma_srq);
	int rc;

	if (!rdma_srq) {
		return 0;
	}

	if (rdma_srq->recv_wrs.first != NULL) {
		SPDK_WARNLOG("Destroying RDMA SRQ with queued recv WRs\n");
	}

	rc = spdk_mlx5_srq_destroy(dv_srq->mlx5_srq);
	if (rc) {
		SPDK_ERRLOG("SRQ destroy failed with %d\n", rc);
	}

	if (!rdma_srq->shared_stats) {
		free(rdma_srq->stats);
	}

	free(dv_srq);

	return rc;
}

bool
spdk_rdma_srq_queue_recv_wrs(struct spdk_rdma_srq *rdma_srq, struct ibv_recv_wr *first)
{
	assert(rdma_srq);
	assert(first);

	struct spdk_rdma_wr_stats *recv_stats = rdma_srq->stats;
	struct spdk_rdma_recv_wr_list *recv_wrs = &rdma_srq->recv_wrs;
	struct mlx5_dv_srq *dv_srq;
	struct ibv_recv_wr *wr;
	bool is_first;

	is_first = recv_wrs->first == NULL;
	if (is_first) {
		recv_wrs->first = first;
	} else {
		recv_wrs->last->next = first;
	}

	dv_srq = SPDK_CONTAINEROF(rdma_srq, struct mlx5_dv_srq, rdma_srq);

	for (wr = first; wr != NULL; wr = wr->next) {
		recv_wrs->last = wr;
		recv_stats->num_submitted_wrs++;

		if (spdk_unlikely(dv_srq->recv_err)) {
			/* Do not post WRs to the SRQ on error. */
			continue;
		}
		dv_srq->recv_err = spdk_mlx5_srq_recv(dv_srq->mlx5_srq, wr->sg_list, wr->num_sge, wr->wr_id);
	}

	return is_first;
}

int
spdk_rdma_srq_flush_recv_wrs(struct spdk_rdma_srq *rdma_srq, struct ibv_recv_wr **bad_wr)
{
	assert(rdma_srq);
	assert(bad_wr);

	struct spdk_rdma_recv_wr_list *recv_wrs = &rdma_srq->recv_wrs;
	struct mlx5_dv_srq *dv_srq;

	if (spdk_unlikely(recv_wrs->first == NULL)) {
		return 0;
	}

	dv_srq = SPDK_CONTAINEROF(rdma_srq, struct mlx5_dv_srq, rdma_srq);
	if (spdk_likely(!dv_srq->recv_err)) {
		spdk_mlx5_srq_complete_recv(dv_srq->mlx5_srq);
	} else {
		*bad_wr = recv_wrs->first;
	}

	recv_wrs->first = NULL;
	rdma_srq->stats->doorbell_updates++;

	return dv_srq->recv_err;
}

bool
spdk_rdma_qp_queue_recv_wrs(struct spdk_rdma_qp *spdk_rdma_qp, struct ibv_recv_wr *first)
{
	assert(spdk_rdma_qp);
	assert(first);

	bool is_first;
	struct spdk_rdma_mlx5_dv_qp *dv_qp;
	struct spdk_rdma_recv_wr_list *recv_wrs = &spdk_rdma_qp->recv_wrs;
	struct spdk_rdma_wr_stats *recv_stats = &spdk_rdma_qp->stats->recv;
	struct ibv_recv_wr *wr;

	is_first = recv_wrs->first == NULL;
	if (is_first) {
		recv_wrs->first = first;
	} else {
		recv_wrs->last->next = first;
	}

	dv_qp = SPDK_CONTAINEROF(spdk_rdma_qp, struct spdk_rdma_mlx5_dv_qp, common);

	for (wr = first; wr != NULL; wr = wr->next) {
		if (!dv_qp->recv_err) {
			dv_qp->recv_err = spdk_mlx5_qp_recv(dv_qp->mlx5_qp, wr->sg_list, wr->num_sge, wr->wr_id);
		}
		recv_wrs->last = wr;
		recv_stats->num_submitted_wrs++;
	}

	return is_first;
}

int
spdk_rdma_qp_flush_recv_wrs(struct spdk_rdma_qp *spdk_rdma_qp, struct ibv_recv_wr **bad_wr)
{
	struct spdk_rdma_mlx5_dv_qp *dv_qp;

	if (spdk_unlikely(spdk_rdma_qp->recv_wrs.first == NULL)) {
		return 0;
	}

	dv_qp = SPDK_CONTAINEROF(spdk_rdma_qp, struct spdk_rdma_mlx5_dv_qp, common);
	if (spdk_likely(!dv_qp->recv_err)) {
		spdk_mlx5_qp_complete_recv(dv_qp->mlx5_qp);
	} else {
		*bad_wr = spdk_rdma_qp->recv_wrs.first;
	}

	spdk_rdma_qp->recv_wrs.first = NULL;
	spdk_rdma_qp->stats->recv.doorbell_updates++;

	return dv_qp->recv_err;
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

	SPDK_DEBUGLOG(rdma_mlx5_dv, "accel seq %p, driver ctx %p\n", seq, &rdma_io_ctx->mlx5);
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

	SPDK_DEBUGLOG(rdma_mlx5_dv, "driver ctx %p, mkey %u\n", &rdma_io_ctx->mlx5,
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
	struct mlx5_dv_cq *dv_cq;
	struct spdk_mlx5_cq_attr mlx5_cq_attr = {
		.cqe_cnt = cq_attr->cqe,
		.cqe_size = 64,
		.cq_context = cq_attr->cq_context,
		.comp_channel = cq_attr->comp_channel,
		.comp_vector = cq_attr->comp_vector
	};
	int rc;

	dv_cq = calloc(1, sizeof(*dv_cq));
	if (!dv_cq) {
		SPDK_ERRLOG("CQ memory allocation failed\n");
		return NULL;
	}

	rc = spdk_mlx5_cq_create(cq_attr->pd, &mlx5_cq_attr, &dv_cq->mlx5_cq);
	if (rc) {
		SPDK_ERRLOG("Failed to create CQ, rc %d\n", rc);
		free(dv_cq);
		return NULL;
	}

	return &dv_cq->rdma_cq;
}

void
spdk_rdma_cq_destroy(struct spdk_rdma_cq *rdma_cq)
{
	assert(rdma_cq);

	struct mlx5_dv_cq *dv_cq = SPDK_CONTAINEROF(rdma_cq, struct mlx5_dv_cq, rdma_cq);

	spdk_mlx5_cq_destroy(dv_cq->mlx5_cq);
	free(dv_cq);
}

int
spdk_rdma_cq_resize(struct spdk_rdma_cq *rdma_cq, int cqe)
{
	assert(rdma_cq);

	struct mlx5_dv_cq *dv_cq = SPDK_CONTAINEROF(rdma_cq, struct mlx5_dv_cq, rdma_cq);

	return spdk_mlx5_cq_resize(dv_cq->mlx5_cq, cqe);
}

int
spdk_rdma_cq_poll(struct spdk_rdma_cq *rdma_cq, int num_entries, struct ibv_wc *wc)
{
	assert(rdma_cq);
	assert(wc);

	struct mlx5_dv_cq *dv_cq = SPDK_CONTAINEROF(rdma_cq, struct mlx5_dv_cq, rdma_cq);

	return spdk_mlx5_cq_poll_wc(dv_cq->mlx5_cq, num_entries, wc);
}

SPDK_LOG_REGISTER_COMPONENT(rdma_mlx5_dv)
