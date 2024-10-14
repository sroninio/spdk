/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "spdk/rpc.h"
#include "spdk/util.h"
#include "fsdev_nfs.h"

struct rpc_nfs_create {
	char *name;
};

static void
free_rpc_nfs_create(struct rpc_nfs_create *req)
{
	free(req->name);
}

static const struct spdk_json_object_decoder rpc_nfs_create_decoders[] = {
	{"name", offsetof(struct rpc_nfs_create, name), spdk_json_decode_string},
};



static void
rpc_nfs_create(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	//We don't param beside name, in our fsdev all the params are hard coded.
	//It can be changed here.
	struct rpc_nfs_create req = {.name = NULL};
	struct spdk_json_write_ctx *w;
	struct spdk_fsdev *fsdev;
	int rc;

	if (spdk_json_decode_object(params, rpc_nfs_create_decoders,
				    SPDK_COUNTOF(rpc_nfs_create_decoders),
				    &req)) {
		SPDK_ERRLOG("spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "spdk_json_decode_object failed");

		free_rpc_nfs_create(&req);
		return;
	}

	rc = spdk_fsdev_nfs_create(&fsdev, req.name);
	if (rc) {
		SPDK_ERRLOG("Failed to create nfs: rc %d\n", rc);
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 spdk_strerror(-rc));
		free_rpc_nfs_create(&req);						 
		return;
	}

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_string(w, fsdev->name);
	spdk_jsonrpc_end_result(request, w);
	free_rpc_nfs_create(&req);						 
}
SPDK_RPC_REGISTER("fsdev_nfs_create", rpc_nfs_create, SPDK_RPC_RUNTIME)

struct rpc_nfs_delete {
	char *name;
};

static const struct spdk_json_object_decoder rpc_nfs_delete_decoders[] = {
	{"name", offsetof(struct rpc_nfs_delete, name), spdk_json_decode_string},
};

static void
rpc_nfs_delete_cb(void *cb_arg, int fsdeverrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (fsdeverrno == 0) {
		spdk_jsonrpc_send_bool_response(request, true);
	} else {
		spdk_jsonrpc_send_error_response(request, fsdeverrno, spdk_strerror(-fsdeverrno));
	}
}

static void
rpc_nfs_delete(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct rpc_nfs_delete req = {};

	if (spdk_json_decode_object(params, rpc_nfs_delete_decoders,
						SPDK_COUNTOF(rpc_nfs_delete_decoders),
						&req)) {
			SPDK_ERRLOG("spdk_json_decode_object failed\n");
			spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
							"spdk_json_decode_object failed");

			free(req.name);
			return;
		}

	spdk_fsdev_nfs_delete(req.name, rpc_nfs_delete_cb, request);
	free(req.name);
}
SPDK_RPC_REGISTER("fsdev_nfs_delete", rpc_nfs_delete, SPDK_RPC_RUNTIME)
