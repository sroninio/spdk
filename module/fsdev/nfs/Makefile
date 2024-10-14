#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#

SPDK_ROOT_DIR := $(abspath $(CURDIR)/../../..)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk

SO_VER := 1
SO_MINOR := 0

C_SRCS = fsdev_nfs.c fsdev_nfs_rpc.c persistent_map.c
CXX_SRCS = volatile_map.cpp


CFLAGS += $(shell pkg-config --cflags glib-2.0)
CXXFLAGS += $(shell pkg-config --cflags glib-2.0)

LIBNAME = fsdev_nfs

SPDK_MAP_FILE = $(SPDK_ROOT_DIR)/mk/spdk_blank.map

include $(SPDK_ROOT_DIR)/mk/spdk.lib.mk
