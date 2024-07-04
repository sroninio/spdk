/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk/env.h"
#include "spdk_internal/xlio.h"
#include "spdk/log.h"

#ifndef SPDK_CONFIG_STATIC_XLIO
static char g_default_xlio_path[] = "libxlio.so";
struct spdk_sock_xlio_ops g_xlio_ops;
struct xlio_api_t *g_xlio_api;
static void *g_xlio_handle;
#endif

#ifndef SPDK_CONFIG_STATIC_XLIO
static int
xlio_load(const char *xlio_path)
{
	g_xlio_handle = dlopen(xlio_path, RTLD_NOW);
	if (!g_xlio_handle) {
		SPDK_ERRLOG("Failed to load XLIO library: path %s, error %s\n",
			    xlio_path, dlerror());
		return -1;
	}

#define GET_SYM(sym) \
	g_xlio_ops.sym = dlsym(g_xlio_handle, #sym); \
	if (!g_xlio_ops.sym) { \
		SPDK_ERRLOG("Failed to find symbol '%s'in XLIO library\n", #sym); \
		dlclose(g_xlio_handle); \
		g_xlio_handle = NULL; \
		return -1; \
	}

	GET_SYM(socket);
	GET_SYM(bind);
	GET_SYM(listen);
	GET_SYM(connect);
	GET_SYM(accept);
	GET_SYM(close);
	GET_SYM(readv);
	GET_SYM(writev);
	GET_SYM(recv);
	GET_SYM(recvmsg);
	GET_SYM(sendmsg);
	GET_SYM(fcntl);
	GET_SYM(ioctl);
	GET_SYM(getsockopt);
	GET_SYM(setsockopt);
	GET_SYM(getsockname);
	GET_SYM(getpeername);
	GET_SYM(getaddrinfo);
	GET_SYM(freeaddrinfo);
	GET_SYM(gai_strerror);
#undef GET_SYM
	return 0;
}

static void
xlio_unload(void)
{
	int rc;

	if (g_xlio_handle) {
		int (*xlio_exit)(void) = dlsym(g_xlio_handle, "xlio_exit");

		if (xlio_exit) {
			xlio_exit();
		}

		memset(&g_xlio_ops, 0, sizeof(g_xlio_ops));
		rc = dlclose(g_xlio_handle);
		if (rc) {
			SPDK_ERRLOG("Closing libxlio failed: rc %d %s\n",
				    rc, dlerror());
		}

		SPDK_NOTICELOG("Unloaded libxlio\n");
		g_xlio_handle = NULL;
	}
}

static struct xlio_api_t *
spdk_xlio_get_api(void)
{
	struct xlio_api_t *api_ptr = NULL;
	socklen_t len = sizeof(api_ptr);

	int err = xlio_getsockopt(-2, SOL_SOCKET, SO_XLIO_GET_API, &api_ptr, &len);
	if (err < 0) {
		return NULL;
	}

	return api_ptr;
}
#endif

static void *
spdk_xlio_alloc(size_t size)
{
	return spdk_zmalloc(size, 0, NULL, SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA);
}

static void
spdk_xlio_free(void *buf)
{
	/* For some reason XLIO destructor is not called from dlclose
	 * but is called later after DPDK cleanup. And this leads to a
	 * crash since all DPDK structures are already freed.
	 *
	 * The check below works this around. If XLIO didn't free the
	 * memory while in dlcose(), don't try to free it. DPDK will
	 * do or has already done the cleanup.
	 */
#ifndef SPDK_CONFIG_STATIC_XLIO
	if (g_xlio_handle) {
		spdk_free(buf);
	}
#else
	spdk_free(buf);
#endif
}

int
spdk_xlio_init(void)
{
	int rc;
	struct xlio_init_attr iattr = {
		.flags = 0,
		.memory_alloc = &spdk_xlio_alloc,
		.memory_free = &spdk_xlio_free,
	};

#ifndef SPDK_CONFIG_STATIC_XLIO
	uint64_t required_caps;
	char *xlio_path;

	/* Before init, g_xlio_api must be NULL */
	assert(g_xlio_api == NULL);

	xlio_path = getenv("SPDK_XLIO_PATH");
	if (!xlio_path) {
		SPDK_NOTICELOG("SPDK_XLIO_PATH is not defined. XLIO socket implementation is disabled.\n");
		return 0;
	} else if (strnlen(xlio_path, 1) == 0) {
		xlio_path = g_default_xlio_path;
		SPDK_NOTICELOG("SPDK_XLIO_PATH is defined but empty. Using default: %s\n", g_default_xlio_path);
	}

	if (xlio_load(xlio_path) != 0) {
		return -1;
	}

	g_xlio_api = spdk_xlio_get_api();
	if (!g_xlio_api) {
		SPDK_ERRLOG("Failed to get XLIO API\n");
		return -1;
	}
	printf("Got XLIO API %p\n", g_xlio_api);

	if (g_xlio_api->magic != XLIO_MAGIC_NUMBER) {
		SPDK_ERRLOG("Unexpected XLIO API magic number: expected %" PRIx64 ", got %" PRIx64 "\n",
			    (uint64_t)XLIO_MAGIC_NUMBER, g_xlio_api->magic);
		return -1;
	}

	required_caps = XLIO_EXTRA_API_XLIO_SOCKET;
	if ((g_xlio_api->cap_mask & required_caps) != required_caps) {
		SPDK_ERRLOG("Required XLIO caps are missing: required %" PRIx64 ", got %" PRIx64 "\n",
			    required_caps, g_xlio_api->cap_mask);
		return -1;
	}
#endif
	rc = xlio_init_ex(&iattr);
	if (rc) {
		SPDK_ERRLOG("xlio_init_ex rc %d (errno=%d)\n", rc, errno);
	}

	return rc;
}

void
spdk_xlio_fini(void)
{
#ifndef SPDK_CONFIG_STATIC_XLIO
	xlio_unload();
	g_xlio_api = NULL;
#else
	/* FIXME: call xlio_exit may cause memory corruption */
	/** xlio_exit(); */
#endif
}
