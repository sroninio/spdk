/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "spdk/rpc.h"
#include "spdk/util.h"
#include "fsdev_nvr.h"

struct rpc_nvr_create {
	char *name;
	char *domain;
	char* mds_addr;
	uint16_t mds_port;
	uint8_t xattr_enabled;
};

static void
free_rpc_nvr_create(struct rpc_nvr_create *req)
{
	free(req->name);
	free(req->domain);
	free(req->mds_addr);
}

static const struct spdk_json_object_decoder rpc_nvr_create_decoders[] = {
	{"name", offsetof(struct rpc_nvr_create, name), spdk_json_decode_string},
	{"domain", offsetof(struct rpc_nvr_create, domain), spdk_json_decode_string},
	{"mds_addr", offsetof(struct rpc_nvr_create, mds_addr), spdk_json_decode_string},
	{"mds_port", offsetof(struct rpc_nvr_create, mds_port), spdk_json_decode_uint16, true},
	{"xattr_enabled", offsetof(struct rpc_nvr_create, xattr_enabled), spdk_json_decode_uint8, true},
};

static void
rpc_nvr_create(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct rpc_nvr_create req = {
		.mds_port = 2049,
		.xattr_enabled = UINT8_MAX,
	};
	struct spdk_json_write_ctx *w;
	struct spdk_fsdev *fsdev;
	bool xattr_enabled = false;
	int rc;

	if (spdk_json_decode_object(params, rpc_nvr_create_decoders,
				    SPDK_COUNTOF(rpc_nvr_create_decoders),
				    &req)) {
		SPDK_ERRLOG("spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "spdk_json_decode_object failed");

		free_rpc_nvr_create(&req);
		return;
	}

	if (req.xattr_enabled != UINT8_MAX) {
		xattr_enabled = !!req.xattr_enabled;
	}

	rc = spdk_fsdev_nvr_create(&fsdev, req.name, req.domain, req.mds_addr, req.mds_port, xattr_enabled);
	if (rc) {
		SPDK_ERRLOG("Failed to create nvr %s: rc %d\n", req.name, rc);
		spdk_jsonrpc_send_error_response(request,
						 SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 spdk_strerror(-rc));
		free_rpc_nvr_create(&req);
		return;
	}

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_string(w, fsdev->name);
	spdk_jsonrpc_end_result(request, w);
	free_rpc_nvr_create(&req);
}
SPDK_RPC_REGISTER("fsdev_nvr_create", rpc_nvr_create, SPDK_RPC_RUNTIME)

struct rpc_nvr_delete {
	char *name;
};

static const struct spdk_json_object_decoder rpc_nvr_delete_decoders[] = {
	{"name", offsetof(struct rpc_nvr_delete, name), spdk_json_decode_string},
};

static void
rpc_nvr_delete_cb(void *cb_arg, int fsdeverrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (fsdeverrno == 0) {
		spdk_jsonrpc_send_bool_response(request, true);
	} else {
		spdk_jsonrpc_send_error_response(request, fsdeverrno, spdk_strerror(-fsdeverrno));
	}
}

static void
rpc_nvr_delete(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct rpc_nvr_delete req = {};

	if (spdk_json_decode_object(params, rpc_nvr_delete_decoders,
				    SPDK_COUNTOF(rpc_nvr_delete_decoders),
				    &req)) {
		SPDK_ERRLOG("spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "spdk_json_decode_object failed");

		free(req.name);
		return;
	}

	spdk_fsdev_nvr_delete(req.name, rpc_nvr_delete_cb, request);
	free(req.name);
}
SPDK_RPC_REGISTER("fsdev_nvr_delete", rpc_nvr_delete, SPDK_RPC_RUNTIME)
