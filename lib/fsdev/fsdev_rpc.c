/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk/log.h"
#include "spdk/rpc.h"
#include "spdk/util.h"
#include "spdk/string.h"
#include "spdk/fsdev.h"

static void
rpc_fsdev_get_opts(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct spdk_json_write_ctx *w;
	struct spdk_fsdev_opts opts = {};
	int rc;

	if (params) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "'fsdev_get_opts' requires no arguments");
		return;
	}

	rc = spdk_fsdev_get_opts(&opts, sizeof(opts));
	if (rc) {
		spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						     "spdk_fsdev_get_opts failed with %d", rc);
		return;
	}

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_object_begin(w);
	spdk_json_write_named_uint32(w, "fsdev_io_pool_size", opts.fsdev_io_pool_size);
	spdk_json_write_named_uint32(w, "fsdev_io_cache_size", opts.fsdev_io_cache_size);
	spdk_json_write_object_end(w);
	spdk_jsonrpc_end_result(request, w);
}
SPDK_RPC_REGISTER("fsdev_get_opts", rpc_fsdev_get_opts, SPDK_RPC_RUNTIME)

struct rpc_fsdev_set_opts {
	uint32_t fsdev_io_pool_size;
	uint32_t fsdev_io_cache_size;
};

static const struct spdk_json_object_decoder rpc_fsdev_set_opts_decoders[] = {
	{"fsdev_io_pool_size", offsetof(struct rpc_fsdev_set_opts, fsdev_io_pool_size), spdk_json_decode_uint32, false},
	{"fsdev_io_cache_size", offsetof(struct rpc_fsdev_set_opts, fsdev_io_cache_size), spdk_json_decode_uint32, false},
};

static void
rpc_fsdev_set_opts(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct rpc_fsdev_set_opts req = {};
	int rc;
	struct spdk_fsdev_opts opts = {};

	if (spdk_json_decode_object(params, rpc_fsdev_set_opts_decoders,
				    SPDK_COUNTOF(rpc_fsdev_set_opts_decoders),
				    &req)) {
		SPDK_ERRLOG("spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "spdk_json_decode_object failed");
		return;
	}

	rc = spdk_fsdev_get_opts(&opts, sizeof(opts));
	if (rc) {
		spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						     "spdk_fsdev_get_opts failed with %d", rc);
		return;
	}

	opts.fsdev_io_pool_size = req.fsdev_io_pool_size;
	opts.fsdev_io_cache_size = req.fsdev_io_cache_size;

	rc = spdk_fsdev_set_opts(&opts);
	if (rc) {
		spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						     "spdk_fsdev_set_opts failed with %d", rc);
		return;
	}

	spdk_jsonrpc_send_bool_response(request, true);
}
SPDK_RPC_REGISTER("fsdev_set_opts", rpc_fsdev_set_opts, SPDK_RPC_RUNTIME)

struct rpc_fsdev_get_fsdevs {
	char *name;
};

static int
rpc_dump_fsdev_info(void *ctx, struct spdk_fsdev *fsdev)
{
	struct spdk_json_write_ctx *w = ctx;
	const char *fsdev_name = spdk_fsdev_get_name(fsdev);
	int i, rc;

	spdk_json_write_object_begin(w);

	spdk_json_write_named_string(w, "name", fsdev_name);

	spdk_json_write_named_string(w, "module_name", spdk_fsdev_get_module_name(fsdev));
	rc = spdk_fsdev_get_memory_domains(fsdev, NULL, 0);
	if (rc > 0) {
		struct spdk_memory_domain **domains = calloc(rc, sizeof(struct spdk_memory_domain *));
		if (domains) {
			i = spdk_fsdev_get_memory_domains(fsdev, domains, rc);
			if (i == rc) {
				spdk_json_write_named_array_begin(w, "memory_domains");
				for (i = 0; i < rc; i++) {
					const char *domain_id = spdk_memory_domain_get_dma_device_id(domains[i]);
					spdk_json_write_object_begin(w);
					if (domain_id) {
						spdk_json_write_named_string(w, "dma_device_id", domain_id);
					} else {
						spdk_json_write_named_null(w, "dma_device_id");
					}
					spdk_json_write_named_int32(w, "dma_device_type",
								    spdk_memory_domain_get_dma_device_type(domains[i]));
					spdk_json_write_object_end(w);
				}
				spdk_json_write_array_end(w);
			} else {
				SPDK_ERRLOG("Unexpected number of memory domains %d (should be %d)\n", i, rc);
			}

			free(domains);
		} else {
			SPDK_ERRLOG("Memory allocation failed\n");
		}
	}

	spdk_json_write_named_object_begin(w, "module_specific");
	spdk_fsdev_dump_info_json(fsdev, w);
	spdk_json_write_object_end(w);

	spdk_json_write_object_end(w);

	return 0;
}

static const struct spdk_json_object_decoder rpc_fsdev_get_fsdevs_decoders[] = {
	{"name", offsetof(struct rpc_fsdev_get_fsdevs, name), spdk_json_decode_string, true},
};

static void
_rpc_fsdev_event_cb(enum spdk_fsdev_event_type type, struct spdk_fsdev *fsdev, void *ctx)
{
	SPDK_NOTICELOG("Unexpected fsdev event type: %d\n", type);
}

static void
rpc_fsdev_get_fsdevs(struct spdk_jsonrpc_request *request,
		     const struct spdk_json_val *params)
{
	struct rpc_fsdev_get_fsdevs req = {};
	struct spdk_json_write_ctx *w;

	if (params && spdk_json_decode_object(params, rpc_fsdev_get_fsdevs_decoders,
					      SPDK_COUNTOF(rpc_fsdev_get_fsdevs_decoders),
					      &req)) {
		SPDK_ERRLOG("spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto out;
	}

	if (req.name) {
		struct spdk_fsdev_desc *fsdev_desc;
		int rc;

		rc = spdk_fsdev_open(req.name, _rpc_fsdev_event_cb, NULL, NULL, &fsdev_desc);
		if (rc) {
			SPDK_ERRLOG("spdk_fsdev_open failed for '%s': rc=%d\n", req.name, rc);
			spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
			goto out;
		}

		w = spdk_jsonrpc_begin_result(request);
		rpc_dump_fsdev_info(w, spdk_fsdev_desc_get_fsdev(fsdev_desc));
		spdk_jsonrpc_end_result(request, w);
		spdk_fsdev_close(fsdev_desc);
	} else {
		w = spdk_jsonrpc_begin_result(request);
		spdk_json_write_array_begin(w);
		spdk_for_each_fsdev(&req, rpc_dump_fsdev_info);
		spdk_json_write_array_end(w);
		spdk_jsonrpc_end_result(request, w);
	}

out:
	free(req.name);
}
SPDK_RPC_REGISTER("fsdev_get_fsdevs", rpc_fsdev_get_fsdevs, SPDK_RPC_RUNTIME)
