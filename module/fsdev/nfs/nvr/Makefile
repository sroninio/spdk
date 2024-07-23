#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#

SPDK_ROOT_DIR := $(abspath $(CURDIR)/../../..)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk

SO_VER := 1
SO_MINOR := 0

C_SRCS = fsdev_nvr.c fsdev_nvr_rpc.c nvr_mgr.c

CFLAGS += $(shell pkg-config --cflags glib-2.0)
CXXFLAGS += $(shell pkg-config --cflags glib-2.0)

LIBNAME = fsdev_nvr

SPDK_MAP_FILE = $(SPDK_ROOT_DIR)/mk/spdk_blank.map

include $(SPDK_ROOT_DIR)/mk/spdk.lib.mk
