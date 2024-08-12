/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2018 Intel Corporation.
 *   All rights reserved.
 */

#include "spdk/rpc.h"
#include "spdk/string.h"
#include "spdk/util.h"
#include "spdk/env.h"
#include "spdk/log.h"

#include "spdk/init.h"

#include "subsystem.h"

static void
rpc_framework_get_subsystems(struct spdk_jsonrpc_request *request,
			     const struct spdk_json_val *params)
{
	struct spdk_json_write_ctx *w;
	struct spdk_subsystem *subsystem;
	struct spdk_subsystem_depend *deps;

	if (params) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "'framework_get_subsystems' requires no arguments");
		return;
	}

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_array_begin(w);
	subsystem = subsystem_get_first();
	while (subsystem != NULL) {
		spdk_json_write_object_begin(w);

		spdk_json_write_named_string(w, "subsystem", subsystem->name);
		spdk_json_write_named_bool(w, "enabled", subsystem->enabled);
		spdk_json_write_named_array_begin(w, "depends_on");
		deps = subsystem_get_first_depend();
		while (deps != NULL) {
			if (strcmp(subsystem->name, deps->name) == 0) {
				spdk_json_write_string(w, deps->depends_on);
			}
			deps = subsystem_get_next_depend(deps);
		}
		spdk_json_write_array_end(w);
		spdk_json_write_object_end(w);
		subsystem = subsystem_get_next(subsystem);
	}
	spdk_json_write_array_end(w);
	spdk_jsonrpc_end_result(request, w);
}

SPDK_RPC_REGISTER("framework_get_subsystems", rpc_framework_get_subsystems, SPDK_RPC_RUNTIME)

struct rpc_framework_get_config_ctx {
	char *name;
};

static const struct spdk_json_object_decoder rpc_framework_get_config_ctx[] = {
	{"name", offsetof(struct rpc_framework_get_config_ctx, name), spdk_json_decode_string},
};

static void
rpc_framework_disable_subsystem(struct spdk_jsonrpc_request *request,
				const struct spdk_json_val *params)
{
	struct rpc_framework_get_config_ctx req = {};
	struct spdk_subsystem *subsystem, *sub_dep;
	struct spdk_subsystem_depend *deps;

	if (spdk_json_decode_object(params, rpc_framework_get_config_ctx,
				    SPDK_COUNTOF(rpc_framework_get_config_ctx), &req)) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, "Invalid arguments");
		return;
	}

	subsystem = subsystem_find(req.name);
	if (!subsystem) {
		spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						     "Subsystem '%s' not found", req.name);
		free(req.name);
		return;
	}

	free(req.name);

	if (!subsystem->enabled) {
		spdk_jsonrpc_send_bool_response(request, true);
		return;
	}

	deps = subsystem_get_first_depend();
	while (deps != NULL) {
		/* No enabled subsystems may depend on this subsystem */
		if (strcmp(subsystem->name, deps->depends_on) == 0) {
			sub_dep = subsystem_find(deps->name);
			if (!sub_dep) {
				spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
								     "Subsystem Parent '%s' not found", deps->name);
				return;
			}

			if (sub_dep->enabled) {
				spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
								     "Subsystem Parent '%s' is enabled", deps->name);
				return;
			}
		}
		deps = subsystem_get_next_depend(deps);
	}

	subsystem->enabled = false;

	spdk_jsonrpc_send_bool_response(request, true);
}

SPDK_RPC_REGISTER("framework_disable_subsystem", rpc_framework_disable_subsystem, SPDK_RPC_STARTUP)

static void
rpc_framework_enable_subsystem(struct spdk_jsonrpc_request *request,
			       const struct spdk_json_val *params)
{
	struct rpc_framework_get_config_ctx req = {};
	struct spdk_subsystem *subsystem, *sub_dep;
	struct spdk_subsystem_depend *deps;

	if (spdk_json_decode_object(params, rpc_framework_get_config_ctx,
				    SPDK_COUNTOF(rpc_framework_get_config_ctx), &req)) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, "Invalid arguments");
		return;
	}

	subsystem = subsystem_find(req.name);
	if (!subsystem) {
		spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						     "Subsystem '%s' not found", req.name);
		free(req.name);
		return;
	}

	free(req.name);

	if (subsystem->enabled) {
		spdk_jsonrpc_send_bool_response(request, true);
		return;
	}

	deps = subsystem_get_first_depend();
	while (deps != NULL) {
		/* This subsystem may not depend on any disabled subsystems */
		if (strcmp(subsystem->name, deps->name) == 0) {
			sub_dep = subsystem_find(deps->depends_on);
			if (!sub_dep) {
				spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
								     "Subsystem Dependency '%s' not found", sub_dep->name);
				return;
			}

			if (!sub_dep->enabled) {
				spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
								     "Subsystem Dependency '%s' is not enabled", sub_dep->name);
				return;
			}
		}
		deps = subsystem_get_next_depend(deps);
	}

	subsystem->enabled = true;

	spdk_jsonrpc_send_bool_response(request, true);
}

SPDK_RPC_REGISTER("framework_enable_subsystem", rpc_framework_enable_subsystem, SPDK_RPC_STARTUP)

static void
rpc_framework_get_config(struct spdk_jsonrpc_request *request,
			 const struct spdk_json_val *params)
{
	struct rpc_framework_get_config_ctx req = {};
	struct spdk_json_write_ctx *w;
	struct spdk_subsystem *subsystem;

	if (spdk_json_decode_object(params, rpc_framework_get_config_ctx,
				    SPDK_COUNTOF(rpc_framework_get_config_ctx), &req)) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, "Invalid arguments");
		return;
	}

	subsystem = subsystem_find(req.name);
	if (!subsystem) {
		spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						     "Subsystem '%s' not found", req.name);
		free(req.name);
		return;
	}

	free(req.name);

	w = spdk_jsonrpc_begin_result(request);
	subsystem_config_json(w, subsystem);
	spdk_jsonrpc_end_result(request, w);
}

SPDK_RPC_REGISTER("framework_get_config", rpc_framework_get_config, SPDK_RPC_RUNTIME)

static void
dump_pci_device(void *ctx, struct spdk_pci_device *dev)
{
	struct spdk_json_write_ctx *w = ctx;
	struct spdk_pci_addr addr;
	char config[4096], bdf[32];
	int rc;

	addr = spdk_pci_device_get_addr(dev);
	spdk_pci_addr_fmt(bdf, sizeof(bdf), &addr);

	rc = spdk_pci_device_cfg_read(dev, config, sizeof(config), 0);
	if (rc != 0) {
		SPDK_ERRLOG("Failed to read config space of device: %s\n", bdf);
		return;
	}

	spdk_json_write_object_begin(w);
	spdk_json_write_named_string(w, "address", bdf);
	spdk_json_write_named_string(w, "type", spdk_pci_device_get_type(dev));

	/* Don't write the extended config space if it's all zeroes */
	if (spdk_mem_all_zero(&config[256], sizeof(config) - 256)) {
		spdk_json_write_named_bytearray(w, "config_space", config, 256);
	} else {
		spdk_json_write_named_bytearray(w, "config_space", config, sizeof(config));
	}

	spdk_json_write_object_end(w);
}

static void
rpc_framework_get_pci_devices(struct spdk_jsonrpc_request *request,
			      const struct spdk_json_val *params)
{
	struct spdk_json_write_ctx *w;

	if (params != NULL) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "framework_get_pci_devices doesn't accept any parameters.\n");
		return;
	}

	w = spdk_jsonrpc_begin_result(request);

	spdk_json_write_array_begin(w);
	spdk_pci_for_each_device(w, dump_pci_device);
	spdk_json_write_array_end(w);

	spdk_jsonrpc_end_result(request, w);
}
SPDK_RPC_REGISTER("framework_get_pci_devices", rpc_framework_get_pci_devices, SPDK_RPC_RUNTIME)
