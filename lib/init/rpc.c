/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2017 Intel Corporation. All rights reserved.
 *   Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"

#include "spdk/env.h"
#include "spdk/init.h"
#include "spdk/thread.h"
#include "spdk/log.h"
#include "spdk/rpc.h"

#define RPC_SELECT_INTERVAL	4000 /* 4ms */
#define RPC_BUSY_POLL_PERIOD	4000 /* 4ms */

static struct spdk_poller *g_rpc_poller = NULL;
static uint64_t g_busy_period_end = 0;

static int
rpc_subsystem_poll(void *arg)
{
	int rc;
	uint64_t now;

	rc = spdk_rpc_accept();
	now = spdk_get_ticks();
	if (rc > 0) {
		if (g_busy_period_end == 0) {
			spdk_poller_unregister(&g_rpc_poller);
			g_rpc_poller = SPDK_POLLER_REGISTER(rpc_subsystem_poll, NULL, 0);
		}

		g_busy_period_end = now + RPC_BUSY_POLL_PERIOD * (spdk_get_ticks_hz() / SPDK_SEC_TO_USEC);
	} else if (g_busy_period_end != 0 && now >= g_busy_period_end) {
		spdk_poller_unregister(&g_rpc_poller);
		g_rpc_poller = SPDK_POLLER_REGISTER(rpc_subsystem_poll, NULL, RPC_SELECT_INTERVAL);
		g_busy_period_end = 0;
	}

	return SPDK_POLLER_BUSY;
}

static void
rpc_opts_copy(struct spdk_rpc_opts *opts, const struct spdk_rpc_opts *opts_src,
	      size_t size)
{
	assert(opts);
	assert(opts_src);

	opts->size = size;

#define SET_FIELD(field) \
	if (offsetof(struct spdk_rpc_opts, field) + sizeof(opts->field) <= size) { \
		opts->field = opts_src->field; \
	} \

	SET_FIELD(log_file);
	SET_FIELD(log_level);

	/* Do not remove this statement, you should always update this statement when you adding a new field,
	 * and do not forget to add the SET_FIELD statement for your added field. */
	SPDK_STATIC_ASSERT(sizeof(struct spdk_rpc_opts) == 24, "Incorrect size");

#undef SET_FIELD
}

static void
rpc_opts_get_default(struct spdk_rpc_opts *opts, size_t size)
{
	assert(opts);

	opts->size = size;

#define SET_FIELD(field, value) \
	if (offsetof(struct spdk_rpc_opts, field) + sizeof(opts->field) <= size) { \
		opts->field = value; \
	} \

	SET_FIELD(log_file, NULL);
	SET_FIELD(log_level, SPDK_LOG_DISABLED);

#undef SET_FIELD
}

int
spdk_rpc_initialize(const char *listen_addr, const struct spdk_rpc_opts *_opts)
{
	struct spdk_rpc_opts opts;
	int rc;

	if (listen_addr == NULL) {
		/* Not treated as an error */
		return 0;
	}

	if (!spdk_rpc_verify_methods()) {
		return -EINVAL;
	}

	if (_opts != NULL && _opts->size == 0) {
		SPDK_ERRLOG("size in the options structure should not be zero\n");
		return -EINVAL;
	}

	/* Listen on the requested address */
	rc = spdk_rpc_listen(listen_addr);
	if (rc != 0) {
		SPDK_ERRLOG("Unable to start RPC service at %s\n", listen_addr);
		/* TODO: Eventually, treat this as an error. But it historically has not
		 * been and many tests rely on this gracefully failing. */
		return 0;
	}

	rpc_opts_get_default(&opts, sizeof(opts));
	if (_opts != NULL) {
		rpc_opts_copy(&opts, _opts, _opts->size);
	}

	spdk_jsonrpc_set_log_file(opts.log_file);
	spdk_jsonrpc_set_log_level(opts.log_level);

	/* Register a poller to periodically check for RPCs */
	g_rpc_poller = SPDK_POLLER_REGISTER(rpc_subsystem_poll, NULL, RPC_SELECT_INTERVAL);

	return 0;
}

void
spdk_rpc_finish(void)
{
	spdk_rpc_close();
	spdk_poller_unregister(&g_rpc_poller);
}
