#!/usr/bin/env bash
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#

testdir=$(readlink -f $(dirname $0))
rootdir=$(readlink -f $testdir/../..)
source $rootdir/test/common/autotest_common.sh

run_test "accel_mlx5_crypto_split_mb_8_bs_512_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c $testdir/accel_mlx5_crypto_split_8.json \
	-K test_dek -I 1 -b 512
run_test "accel_mlx5_crypto_split_mb_8_bs_512_non_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c $testdir/accel_mlx5_crypto_split_8.json \
	-K test_dek -I 0 -b 512
run_test "accel_mlx5_crypto_split_mb_8_bs_4096_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c $testdir/accel_mlx5_crypto_split_8.json \
	-K test_dek -I 1 -b 4096
run_test "accel_mlx5_crypto_split_mb_8_bs_4096_non_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c $testdir/accel_mlx5_crypto_split_8.json \
	-K test_dek -I 0 -b 4096

run_test "accel_mlx5_crypto_split_mb_12_bs_512_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c $testdir/accel_mlx5_crypto_split_12.json \
	-K test_dek -I 1 -b 512
run_test "accel_mlx5_crypto_split_mb_12_bs_512_non_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c $testdir/accel_mlx5_crypto_split_12.json \
	-K test_dek -I 0 -b 512
run_test "accel_mlx5_crypto_split_mb_12_bs_4096_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c $testdir/accel_mlx5_crypto_split_12.json \
	-K test_dek -I 1 -b 4096
run_test "accel_mlx5_crypto_split_mb_12_bs_4096_non_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c $testdir/accel_mlx5_crypto_split_12.json \
	-K test_dek -I 0 -b 4096

run_test "accel_mlx5_crypto_no_split_bs_512_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c $testdir/accel_mlx5_crypto.json \
	-K test_dek -I 1 -b 512
run_test "accel_mlx5_crypto_no_split_bs_512_non_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c $testdir/accel_mlx5_crypto.json \
	-K test_dek -I 0 -b 512
run_test "accel_mlx5_crypto_no_split_bs_4096_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c $testdir/accel_mlx5_crypto.json \
	-K test_dek -I 1 -b 4096
run_test "accel_mlx5_crypto_no_split_bs_4096_non_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c $testdir/accel_mlx5_crypto.json \
	-K test_dek -I 0 -b 4096
