#!/usr/bin/env bash
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2023-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# vim: filetype=bash:
#
# shellcheck disable=SC2086,SC1091,SC1073,SC1072,SC1009
testdir=$(readlink -f "$(dirname $0)")
rootdir=$(readlink -f $testdir/../..)
source $rootdir/test/common/autotest_common.sh

run_test "accel_crc32c" $SPDK_EXAMPLE_DIR/accel_perf -t 1 -y -q 64 -w crc32c -m 0xf -c $testdir/accel_mlx5.json
run_test "accel_copy_crc32c" $SPDK_EXAMPLE_DIR/accel_perf -t 1 -y -q 64 -w copy_crc32c -m 0xf -c $testdir/accel_mlx5.json
run_test "accel_check_crc32c" $SPDK_EXAMPLE_DIR/accel_perf -t 1 -y -q 64 -w check_crc32c -m 0xf -c $testdir/accel_mlx5.json
run_test "accel_copy_check_crc32c" $SPDK_EXAMPLE_DIR/accel_perf -t 1 -y -q 64 -w copy_check_crc32c -m 0xf -c $testdir/accel_mlx5.json 2>&1 |grep -v "Failed to execute check_crc32c operation, sequence:"

run_test "accel_mlx5_crc32c" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w crc32c -m 0xf -c $testdir/accel_mlx5.json
run_test "accel_mlx5_copy_crc32c" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w copy_crc32c -m 0xf -c $testdir/accel_mlx5.json
run_test "accel_mlx5_check_crc32c" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w check_crc32c -m 0xf -c $testdir/accel_mlx5.json
run_test "accel_mlx5_copy_check_crc32c" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w copy_check_crc32c -m 0xf -c $testdir/accel_mlx5.json 2>&1 |grep -v "Failed to execute check_crc32c operation, sequence:"
run_test "accel_mlx5_crc32c" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 128 -w crc32c -m 0xf -c $testdir/accel_mlx5.json 2>&1 |grep -v "Failed to execute check_crc32c operation, sequence:"
run_test "accel_mlx5_copy_crc32c" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 128 -w copy_crc32c -m 0xf -c $testdir/accel_mlx5.json 2>&1 |grep -v "Failed to execute check_crc32c operation, sequence:"
run_test "accel_mlx5_check_crc32c" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 128 -w check_crc32c -m 0xf -c $testdir/accel_mlx5.json 2>&1 |grep -v "Failed to execute check_crc32c operation, sequence:"
run_test "accel_mlx5_copy_check_crc32c" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 128 -w copy_check_crc32c -m 0xf -c $testdir/accel_mlx5.json 2>&1 |grep -v "Failed to execute check_crc32c operation, sequence:"
run_test "accel_mlx5_check_crc32c_error" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 1 -w check_crc32c -m 0x1 -f -c $testdir/accel_mlx5.json 2>&1 |grep -v "Failed to execute check_crc32c operation, sequence:"
run_test "accel_mlx5_copy_check_crc32c_error" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 1 -w copy_check_crc32c -m 0x1 -f -c $testdir/accel_mlx5.json 2>&1 |grep -v "Failed to execute check_crc32c operation, sequence:"
