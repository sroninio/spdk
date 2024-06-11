/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2020 Intel Corporation. All rights reserved.
 *   Copyright (c) Mellanox Technologies LTD. All rights reserved.
 *   Copyright (c) 2023-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include <rdma/rdma_cma.h>

#include "spdk/stdinc.h"
#include "spdk/string.h"
#include "spdk/likely.h"

#include "spdk_internal/rdma.h"
#include "spdk/log.h"

struct spdk_rdma_qp *
spdk_rdma_qp_create(struct rdma_cm_id *cm_id, struct spdk_rdma_qp_init_attr *qp_attr)
{
	struct spdk_rdma_qp *spdk_rdma_qp;
	int rc;
	struct ibv_qp_init_attr attr = {
		.qp_context = qp_attr->qp_context,
		.send_cq = qp_attr->cq->cq,
		.recv_cq = qp_attr->cq->cq,
		.srq = qp_attr->srq->srq,
		.cap = qp_attr->cap,
		.qp_type = IBV_QPT_RC
	};

	spdk_rdma_qp = calloc(1, sizeof(*spdk_rdma_qp));
	if (!spdk_rdma_qp) {
		SPDK_ERRLOG("qp memory allocation failed\n");
		return NULL;
	}

	if (qp_attr->stats) {
		spdk_rdma_qp->stats = qp_attr->stats;
		spdk_rdma_qp->shared_stats = true;
	} else {
		spdk_rdma_qp->stats = calloc(1, sizeof(*spdk_rdma_qp->stats));
		if (!spdk_rdma_qp->stats) {
			SPDK_ERRLOG("qp statistics memory allocation failed\n");
			free(spdk_rdma_qp);
			return NULL;
		}
	}

	rc = rdma_create_qp(cm_id, qp_attr->pd, &attr);
	if (rc) {
		SPDK_ERRLOG("Failed to create qp, errno %s (%d)\n", spdk_strerror(errno), errno);
		free(spdk_rdma_qp);
		return NULL;
	}

	qp_attr->cap = attr.cap;
	spdk_rdma_qp->qp = cm_id->qp;
	spdk_rdma_qp->cm_id = cm_id;

	return spdk_rdma_qp;
}

int
spdk_rdma_qp_accept(struct spdk_rdma_qp *spdk_rdma_qp, struct rdma_conn_param *conn_param)
{
	assert(spdk_rdma_qp != NULL);
	assert(spdk_rdma_qp->cm_id != NULL);

	return rdma_accept(spdk_rdma_qp->cm_id, conn_param);
}

int
spdk_rdma_qp_complete_connect(struct spdk_rdma_qp *spdk_rdma_qp)
{
	/* Nothing to be done for Verbs */
	return 0;
}

void
spdk_rdma_qp_destroy(struct spdk_rdma_qp *spdk_rdma_qp)
{
	assert(spdk_rdma_qp != NULL);

	if (spdk_rdma_qp->send_wrs.first != NULL) {
		SPDK_WARNLOG("Destroying qpair with queued Work Requests\n");
	}

	if (spdk_rdma_qp->qp) {
		rdma_destroy_qp(spdk_rdma_qp->cm_id);
	}

	if (!spdk_rdma_qp->shared_stats) {
		free(spdk_rdma_qp->stats);
	}

	free(spdk_rdma_qp);
}

int
spdk_rdma_qp_disconnect(struct spdk_rdma_qp *spdk_rdma_qp)
{
	int rc = 0;

	assert(spdk_rdma_qp != NULL);

	if (spdk_rdma_qp->cm_id) {
		rc = rdma_disconnect(spdk_rdma_qp->cm_id);
		if (rc) {
			if (errno == EINVAL && spdk_rdma_qp->qp->context->device->transport_type == IBV_TRANSPORT_IWARP) {
				/* rdma_disconnect may return an error and set errno to EINVAL in case of iWARP.
				 * This behaviour is expected since iWARP handles disconnect event other than IB and
				 * qpair is already in error state when we call rdma_disconnect */
				return 0;
			}
			SPDK_ERRLOG("rdma_disconnect failed, errno %s (%d)\n", spdk_strerror(errno), errno);
		}
	}

	return rc;
}

bool
spdk_rdma_qp_queue_send_wrs(struct spdk_rdma_qp *spdk_rdma_qp, struct ibv_send_wr *first)
{
	struct ibv_send_wr *last;

	assert(spdk_rdma_qp);
	assert(first);

	spdk_rdma_qp->stats->send.num_submitted_wrs++;
	last = first;
	while (last->next != NULL) {
		last = last->next;
		spdk_rdma_qp->stats->send.num_submitted_wrs++;
	}

	if (spdk_rdma_qp->send_wrs.first == NULL) {
		spdk_rdma_qp->send_wrs.first = first;
		spdk_rdma_qp->send_wrs.last = last;
		return true;
	} else {
		spdk_rdma_qp->send_wrs.last->next = first;
		spdk_rdma_qp->send_wrs.last = last;
		return false;
	}
}

int
spdk_rdma_qp_flush_send_wrs(struct spdk_rdma_qp *spdk_rdma_qp, struct ibv_send_wr **bad_wr)
{
	int rc;

	assert(spdk_rdma_qp);
	assert(bad_wr);

	if (spdk_unlikely(!spdk_rdma_qp->send_wrs.first)) {
		return 0;
	}

	rc = ibv_post_send(spdk_rdma_qp->qp, spdk_rdma_qp->send_wrs.first, bad_wr);

	spdk_rdma_qp->send_wrs.first = NULL;
	spdk_rdma_qp->stats->send.doorbell_updates++;

	return rc;
}

struct spdk_rdma_srq *
spdk_rdma_srq_create(struct spdk_rdma_srq_init_attr *init_attr)
{
	assert(init_attr);
	assert(init_attr->pd);

	struct spdk_rdma_srq *rdma_srq = calloc(1, sizeof(*rdma_srq));

	if (!rdma_srq) {
		SPDK_ERRLOG("Can't allocate memory for SRQ handle\n");
		return NULL;
	}

	if (init_attr->stats) {
		rdma_srq->stats = init_attr->stats;
		rdma_srq->shared_stats = true;
	} else {
		rdma_srq->stats = calloc(1, sizeof(*rdma_srq->stats));
		if (!rdma_srq->stats) {
			SPDK_ERRLOG("SRQ statistics memory allocation failed");
			free(rdma_srq);
			return NULL;
		}
	}

	rdma_srq->srq = ibv_create_srq(init_attr->pd, &init_attr->srq_init_attr);
	if (!rdma_srq->srq) {
		if (!init_attr->stats) {
			free(rdma_srq->stats);
		}
		SPDK_ERRLOG("Unable to create SRQ, errno %d (%s)\n", errno, spdk_strerror(errno));
		free(rdma_srq);
		return NULL;
	}

	return rdma_srq;
}

int
spdk_rdma_srq_destroy(struct spdk_rdma_srq *rdma_srq)
{
	int rc;

	if (!rdma_srq) {
		return 0;
	}

	assert(rdma_srq->srq);

	if (rdma_srq->recv_wrs.first != NULL) {
		SPDK_WARNLOG("Destroying RDMA SRQ with queued recv WRs\n");
	}

	rc = ibv_destroy_srq(rdma_srq->srq);
	if (rc) {
		SPDK_ERRLOG("SRQ destroy failed with %d\n", rc);
	}

	if (!rdma_srq->shared_stats) {
		free(rdma_srq->stats);
	}

	free(rdma_srq);

	return rc;
}

static inline bool
rdma_queue_recv_wrs(struct spdk_rdma_recv_wr_list *recv_wrs, struct ibv_recv_wr *first,
		    struct spdk_rdma_wr_stats *recv_stats)
{
	struct ibv_recv_wr *last;

	recv_stats->num_submitted_wrs++;
	last = first;
	while (last->next != NULL) {
		last = last->next;
		recv_stats->num_submitted_wrs++;
	}

	if (recv_wrs->first == NULL) {
		recv_wrs->first = first;
		recv_wrs->last = last;
		return true;
	} else {
		recv_wrs->last->next = first;
		recv_wrs->last = last;
		return false;
	}
}

bool
spdk_rdma_srq_queue_recv_wrs(struct spdk_rdma_srq *rdma_srq, struct ibv_recv_wr *first)
{
	assert(rdma_srq);
	assert(first);

	return rdma_queue_recv_wrs(&rdma_srq->recv_wrs, first, rdma_srq->stats);
}

int
spdk_rdma_srq_flush_recv_wrs(struct spdk_rdma_srq *rdma_srq, struct ibv_recv_wr **bad_wr)
{
	int rc;

	if (spdk_unlikely(rdma_srq->recv_wrs.first == NULL)) {
		return 0;
	}

	rc = ibv_post_srq_recv(rdma_srq->srq, rdma_srq->recv_wrs.first, bad_wr);

	rdma_srq->recv_wrs.first = NULL;
	rdma_srq->stats->doorbell_updates++;

	return rc;
}

bool
spdk_rdma_qp_queue_recv_wrs(struct spdk_rdma_qp *spdk_rdma_qp, struct ibv_recv_wr *first)
{
	assert(spdk_rdma_qp);
	assert(first);

	return rdma_queue_recv_wrs(&spdk_rdma_qp->recv_wrs, first, &spdk_rdma_qp->stats->recv);
}

int
spdk_rdma_qp_flush_recv_wrs(struct spdk_rdma_qp *spdk_rdma_qp, struct ibv_recv_wr **bad_wr)
{
	int rc;

	if (spdk_unlikely(spdk_rdma_qp->recv_wrs.first == NULL)) {
		return 0;
	}

	rc = ibv_post_recv(spdk_rdma_qp->qp, spdk_rdma_qp->recv_wrs.first, bad_wr);

	spdk_rdma_qp->recv_wrs.first = NULL;
	spdk_rdma_qp->stats->recv.doorbell_updates++;

	return rc;
}

size_t
spdk_rdma_get_io_context_size(void)
{
	return 0;
}

bool
spdk_rdma_accel_sequence_supported(struct spdk_rdma_qp *qp)
{
	return false;
}

int
spdk_rdma_accel_sequence_finish(struct spdk_rdma_qp *qp, void *rdma_io_ctx,
				struct spdk_accel_sequence *seq, spdk_rdma_accel_seq_cb cb_fn, void *cb_ctx)
{
	return -ENOTSUP;
}

int
spdk_rdma_accel_seq_get_translation(void *rdma_io_ctx,
				    struct  spdk_rdma_memory_translation_ctx *translation)
{
	return -ENOTSUP;
}

int
spdk_rdma_accel_sequence_release(struct spdk_rdma_qp *qp, void *_rdma_io_ctx)
{
	return -ENOTSUP;
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
