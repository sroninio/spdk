#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2023-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#

SPDK_ROOT_DIR := $(abspath $(CURDIR)/../../..)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk
include $(SPDK_ROOT_DIR)/mk/spdk.modules.mk

APP = accel_mlx5_test

C_SRCS := accel_mlx5_test.c

SPDK_LIB_LIST = $(ACCEL_MODULES_LIST) event event_accel

include $(SPDK_ROOT_DIR)/mk/spdk.app.mk
