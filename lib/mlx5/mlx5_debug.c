/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/log.h"

#include "mlx5_priv.h"

#ifdef DEBUG
extern struct spdk_log_flag SPDK_LOG_mlx5_wqe_dump;

void
mlx5_qp_dump_sq_wqe(struct spdk_mlx5_qp *qp, int n_wqe_bb)
{
	struct spdk_mlx5_hw_qp *hw = &qp->hw;
	uint32_t pi;
	uint32_t to_end;
	uint32_t *wqe;
	int i;

	if (!SPDK_LOG_mlx5_wqe_dump.enabled) {
		return;
	}

	pi = hw->sq_pi & (hw->sq_wqe_cnt - 1);
	to_end = (hw->sq_wqe_cnt - pi) * MLX5_SEND_WQE_BB;
	wqe = mlx5_qp_get_wqe_bb(hw);

	SPDK_DEBUGLOG(mlx5_wqe_dump, "QP: qpn 0x%" PRIx32 ", wqe_index 0x%" PRIx32 ", addr %p\n",
		      hw->qp_num, pi, wqe);
	for (i = 0; i < n_wqe_bb; i++) {
		fprintf(stderr,
			"%08" PRIx32 " %08" PRIx32 " %08" PRIx32 " %08" PRIx32 "\n"
			"%08" PRIx32 " %08" PRIx32 " %08" PRIx32 " %08" PRIx32 "\n"
			"%08" PRIx32 " %08" PRIx32 " %08" PRIx32 " %08" PRIx32 "\n"
			"%08" PRIx32 " %08" PRIx32 " %08" PRIx32 " %08" PRIx32 "\n",
			be32toh(wqe[0]),  be32toh(wqe[1]),  be32toh(wqe[2]),  be32toh(wqe[3]),
			be32toh(wqe[4]),  be32toh(wqe[5]),  be32toh(wqe[6]),  be32toh(wqe[7]),
			be32toh(wqe[8]),  be32toh(wqe[9]),  be32toh(wqe[10]), be32toh(wqe[11]),
			be32toh(wqe[12]), be32toh(wqe[13]), be32toh(wqe[14]), be32toh(wqe[15]));
		wqe = mlx5_qp_get_next_wqbb(hw, &to_end, wqe);
	}
}

void
mlx5_qp_dump_rq_wqe(struct spdk_mlx5_qp *qp, int index)
{
	struct spdk_mlx5_hw_qp *hw_qp = &qp->hw;
	uint32_t *dseg;
	size_t dumped_bytes;

	if (!SPDK_LOG_mlx5_wqe_dump.enabled) {
		return;
	}

	dseg = (void *)hw_qp->rq_addr + index * hw_qp->rq_stride;
	SPDK_DEBUGLOG(mlx5_wqe_dump, "QP: qpn 0x%" PRIx32 ", wqe_index 0x%x, addr %p\n",
		      hw_qp->qp_num, index, dseg);

	/* The RQ WQE stride is aligned to 16 bytes (size of the data segment entry) */
	for (dumped_bytes = 0; dumped_bytes < hw_qp->rq_stride; dumped_bytes += 16) {
		fprintf(stderr,
			"%08" PRIx32 " %08" PRIx32 " %08" PRIx32 " %08" PRIx32 "\n",
			be32toh(dseg[0]),  be32toh(dseg[1]),  be32toh(dseg[2]),  be32toh(dseg[3]));
	}
}

void
mlx5_srq_dump_wqe(struct spdk_mlx5_srq *srq, int index)
{
	uint32_t *wqe;
	uint32_t dumped_bytes;

	if (!SPDK_LOG_mlx5_wqe_dump.enabled) {
		return;
	}

	wqe = mlx5_srq_get_wqe(&srq->hw, index);

	SPDK_DEBUGLOG(mlx5_srq, "SRQ: srqn 0x%" PRIx32 ", wqe_index 0x%" PRIx32 ", addr %p\n",
		      srq->hw.srqn, srq->hw.head, wqe);
	for (dumped_bytes = 0; dumped_bytes < srq->hw.stride; dumped_bytes += 64, wqe += 16) {
		fprintf(stderr,
			"%08" PRIx32 " %08" PRIx32 " %08" PRIx32 " %08" PRIx32 "\n"
			"%08" PRIx32 " %08" PRIx32 " %08" PRIx32 " %08" PRIx32 "\n"
			"%08" PRIx32 " %08" PRIx32 " %08" PRIx32 " %08" PRIx32 "\n"
			"%08" PRIx32 " %08" PRIx32 " %08" PRIx32 " %08" PRIx32 "\n",
			be32toh(wqe[0]),  be32toh(wqe[1]),  be32toh(wqe[2]),  be32toh(wqe[3]),
			be32toh(wqe[4]),  be32toh(wqe[5]),  be32toh(wqe[6]),  be32toh(wqe[7]),
			be32toh(wqe[8]),  be32toh(wqe[9]),  be32toh(wqe[10]), be32toh(wqe[11]),
			be32toh(wqe[12]), be32toh(wqe[13]), be32toh(wqe[14]), be32toh(wqe[15]));
	}
}
#endif /* DEBUG */

SPDK_LOG_REGISTER_COMPONENT(mlx5_wqe_dump)
