#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (C) 2016 Intel Corporation.
#  Copyright (c) 2023-2024 NVIDIA CORPORATION & AFFILIATES.
#  All rights reserved.
#

SPDK_ROOT_DIR := $(abspath $(CURDIR)/../../../../..)

SPDK_LIB_LIST = conf util

SCSI_OBJS = port
ISCSI_OBJS = param
UTIL_OBJS = md5
LIBS += $(SCSI_OBJS:%=$(SPDK_ROOT_DIR)/lib/scsi/%.o)
LIBS += $(ISCSI_OBJS:%=$(SPDK_ROOT_DIR)/lib/iscsi/%.o)
LIBS += $(UTIL_OBJS:%=$(SPDK_ROOT_DIR)/lib/util/%.o)
LIBS += -lcunit

TEST_FILE = iscsi_ut.c

include $(SPDK_ROOT_DIR)/mk/spdk.unittest.mk
