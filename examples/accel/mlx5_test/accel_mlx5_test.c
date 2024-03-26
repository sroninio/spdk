/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2020 Intel Corporation.
 *   Copyright (c) 2023-2024 NVIDIA CORPORATION & AFFILIATES.
 *   All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk/thread.h"
#include "spdk/env.h"
#include "spdk/event.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "spdk/accel.h"
#include "spdk/crc32.h"
#include "spdk/util.h"
#include "spdk_internal/md5.h"

#define DATA_PATTERN 0x5a
#define ALIGN_4K 0x1000
#define COMP_BUF_PAD_PERCENTAGE 1.1L
#define MAX_XFER_SIZE (1024 * 128)
#define MAX_IOVS 32

static uint64_t	g_tsc_rate;
static uint64_t g_tsc_end;
static int g_rc;
static int g_queue_depth = 32;
/* g_allocate_depth indicates how many tasks we allocate per worker. It will
 * be at least as much as the queue depth.
 */
static int g_allocate_depth = 0;
static int g_threads_per_core = 1;
static int g_time_in_sec = 5;
static uint32_t g_crc32c_seed = 0xffffffffUL;
static const char *g_workload_type = NULL;
static enum spdk_accel_opcode g_workload_selection;
static struct worker_thread *g_workers = NULL;
static int g_num_workers = 0;
static pthread_mutex_t g_workers_lock = PTHREAD_MUTEX_INITIALIZER;
static struct spdk_app_opts g_opts = {};
static const char *g_crypto_key_name;
static struct spdk_accel_crypto_key *g_crypto_key;
static uint32_t g_block_size = 512;
static bool g_inplace = true;
static bool g_crc_error = false;

struct worker_thread;
static void accel_done(void *ref, int status);
static void encrypt_done(void *ref, int status);

struct display_info {
	int core;
	int thread;
};

struct ap_task {
	void			*src;
	struct iovec		*src_iovs;
	uint32_t		src_iovcnt;
	struct iovec		*dst_iovs;
	uint32_t		dst_iovcnt;
	void			*dst;
	uint32_t		*crc_dst;
	struct worker_thread	*worker;
	const struct ap_test	*test;
	uint64_t		iv;
	uint8_t			src_md5[SPDK_MD5DIGEST_LEN];
	int			test_idx;
	TAILQ_ENTRY(ap_task)	link;
};

struct worker_thread {
	struct spdk_io_channel		*ch;
	uint64_t			xfer_completed;
	uint64_t			xfer_failed;
	uint64_t			injected_miscompares;
	uint64_t			current_queue_depth;
	TAILQ_HEAD(, ap_task)		tasks_pool;
	struct worker_thread		*next;
	unsigned			core;
	struct spdk_thread		*thread;
	bool				is_draining;
	struct spdk_poller		*is_draining_poller;
	struct spdk_poller		*stop_poller;
	void				*task_base;
	struct display_info		display;
	enum spdk_accel_opcode		workload;
};

struct ap_test {
	uint32_t src[MAX_IOVS];
	uint32_t dst[MAX_IOVS];
};

static const struct ap_test ap_tests[] = {
	{
		.src = { 4096, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
		.dst = { 4096, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
	},
	{
		.src = { 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
		.dst = { 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 1024, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
	},
	{
		.src = { 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 1024, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
		.dst = { 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
	},
	{
		.src = { 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
		.dst = { 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 1024, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
	},
	{
		.src = { 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 1024, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
		.dst = { 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
	},
	{
		.src = { 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024 },
		.dst = { 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024 },
	},
	{
		.src = { 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024 },
		.dst = { 1024 * 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
	},
	{
		.src = { 1024 * 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
		.dst = { 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024 },
	},
	{
		.src = { 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
		.dst = { 1024 * 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
	},
	{
		.src = { 1024 * 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
		.dst = { 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
	},
	{
		.src = { 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024 + 512, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
		.dst = { 1024 * 16, 512, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
	},
	{
		.src = { 1024 * 16, 512, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
		.dst = { 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024 + 512, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
	},
	{
		.src = { 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024 },
		.dst = { 1024 * 18, 1024 * 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
	},
	{
		.src = { 1024 * 18, 1024 * 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
		.dst = { 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024 },
	},
};

/* Additional cases for crypto with 512 byte block size */
static const struct ap_test ap_tests_crypto_bs_512[] = {
	/* Overflow of src iovs on encrypt and dst iovs on decrypt. Last iov is on block size boundary for 512B data blocks */
	{
		.src = { 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 2176, 28544, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
		.dst = { 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024 },
	},
	/* Overflow of src iovs on encrypt and dst iovs on decrypt. Last iov is not on block size boundary for 512B data blocks */
	{
		.src = { 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 123, 2181, 28544, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
		.dst = { 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024 },
	},
	/* Overflow of src and then dst iovs on encrypt and on decrypt. Last iov is not on block size boundary for 512B data blocks */
	{
		.src = { 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 123, 2181, 28544, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
		.dst = { 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 61, 2181, 29566, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}
};

/* Additional cases for crypto with 4KiB byte block size */
static const struct ap_test ap_tests_crypto_bs_4096[] = {
	/* Overflow of src iovs on encrypt and dst iovs on decrypt. Last iov is on block size boundary for 4KiB data blocks */
	{
		.src = { 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 2176, 14208, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
		.dst = { 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024 },
	},
	/* Overflow of src iovs on encrypt and dst iovs on decrypt. Last iov is not on block size boundary for 4KiB data blocks */
	{
		.src = { 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1019, 1029, 15360, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
		.dst = { 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024 },
	},
	/* Overflow of src and then dst iovs on encrypt and on decrypt. Last iov is not on block size boundary for 4KiB data blocks */
	{
		.src = { 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1019, 1029, 15360, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
		.dst = { 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 509, 2181, 22398, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}
};

static void
dump_user_config(void)
{
	const char *module_name = NULL;
	int rc;

	rc = spdk_accel_get_opc_module_name(g_workload_selection, &module_name);
	if (rc) {
		printf("error getting module name (%d)\n", rc);
	}

	printf("\nSPDK Configuration:\n");
	printf("Core mask:      %s\n\n", g_opts.reactor_mask);
	printf("Accel Perf Configuration:\n");
	printf("Workload Type:  %s\n", g_workload_type);
	if (g_workload_selection == SPDK_ACCEL_OPC_CRC32C ||
	    g_workload_selection == SPDK_ACCEL_OPC_COPY_CRC32C ||
	    g_workload_selection == SPDK_ACCEL_OPC_CHECK_CRC32C ||
	    g_workload_selection == SPDK_ACCEL_OPC_COPY_CHECK_CRC32C) {
		printf("CRC-32C seed:   %u\n", g_crc32c_seed);
	}
	if (g_workload_selection == SPDK_ACCEL_OPC_CHECK_CRC32C ||
	    g_workload_selection == SPDK_ACCEL_OPC_COPY_CHECK_CRC32C) {
		printf("Inject CRC-32C error:   %u\n", g_crc_error);
	}
	if (g_workload_selection == SPDK_ACCEL_OPC_ENCRYPT ||
	    g_workload_selection == SPDK_ACCEL_OPC_DECRYPT) {
		printf("Crypto key:   %s\n", g_crypto_key_name);
		printf("Block size:   %u\n", g_block_size);
		printf("Inplace op:   %s\n", g_inplace ? "true" : "false");
	}
	printf("Module:         %s\n", module_name);
	printf("Queue depth:    %u\n", g_queue_depth);
	printf("Allocate depth: %u\n", g_allocate_depth);
	printf("# threads/core: %u\n", g_threads_per_core);
	printf("Run time:       %u seconds\n", g_time_in_sec);
}

static void
usage(void)
{
	printf("accel_perf options:\n");
	printf("\t[-h help message]\n");
	printf("\t[-q queue depth per core]\n");
	printf("\t[-T number of threads per core\n");
	printf("\t[-n number of channels]\n");
	printf("\t[-t time in seconds]\n");
	printf("\t[-w workload type must be one of these: crc32c, copy_crc32c, check_crc32c, copy_check_crc32c, encrypt, decrypt\n");
	printf("\t[-a tasks to allocate per core (default: same value as -q)]\n");
	printf("\t\tCan be used to spread operations across a wider range of memory.\n");
	printf("\t[-K crypto key name (used by crypto)]\n");
	printf("\t[-I inplace task if 1 (both src and dst buffers are used), out-of-place if 0 (only src is used)]\n");
	printf("\t[-b crypto block size]\n");
	printf("\t[-f inject crc error]\n");
}

static int
parse_args(int argc, char *argv)
{
	int argval = 0;

	switch (argc) {
	case 'a':
	case 'b':
	case 'I':
	case 'T':
	case 'q':
	case 't':
		argval = spdk_strtol(optarg, 10);
		if (argval < 0) {
			fprintf(stderr, "-%c option must be non-negative.\n", argc);
			usage();
			return 1;
		}
		break;
	default:
		break;
	};

	switch (argc) {
	case 'a':
		g_allocate_depth = argval;
		break;
	case 'b':
		g_block_size = argval;
		break;
	case 'f':
		g_crc_error = true;
		break;
	case 'I':
		g_inplace = !!argval;
		break;
	case 'T':
		g_threads_per_core = argval;
		break;
	case 'q':
		g_queue_depth = argval;
		break;
	case 't':
		g_time_in_sec = argval;
		break;
	case 'w':
		g_workload_type = optarg;
		if (!strcmp(g_workload_type, "crc32c")) {
			g_workload_selection = SPDK_ACCEL_OPC_CRC32C;
		} else if (!strcmp(g_workload_type, "copy_crc32c")) {
			g_workload_selection = SPDK_ACCEL_OPC_COPY_CRC32C;
		} else if (!strcmp(g_workload_type, "check_crc32c")) {
			g_workload_selection = SPDK_ACCEL_OPC_CHECK_CRC32C;
		} else if (!strcmp(g_workload_type, "copy_check_crc32c")) {
			g_workload_selection = SPDK_ACCEL_OPC_COPY_CHECK_CRC32C;
		} else if (!strcmp(g_workload_type, "encrypt")) {
			g_workload_selection = SPDK_ACCEL_OPC_ENCRYPT;
		} else if (!strcmp(g_workload_type, "decrypt")) {
			g_workload_selection = SPDK_ACCEL_OPC_DECRYPT;
		} else {
			usage();
			return 1;
		}
		break;
	case 'K':
		g_crypto_key_name = optarg;
		break;
	default:
		usage();
		return 1;
	}

	return 0;
}

static int dump_result(void);
static void
unregister_worker(void *arg1)
{
	struct worker_thread *worker = arg1;

	free(worker->task_base);
	spdk_put_io_channel(worker->ch);
	spdk_thread_exit(spdk_get_thread());
	pthread_mutex_lock(&g_workers_lock);
	assert(g_num_workers >= 1);
	if (--g_num_workers == 0) {
		pthread_mutex_unlock(&g_workers_lock);
		/* Only dump results on successful runs */
		if (g_rc == 0) {
			g_rc = dump_result();
		}
		spdk_app_stop(g_rc);
	} else {
		pthread_mutex_unlock(&g_workers_lock);
	}
}

static int
_get_crc_task_data_bufs(struct ap_task *task)
{
	task->src_iovcnt = MAX_IOVS;
	task->src_iovs = calloc(task->src_iovcnt, sizeof(struct iovec));
	if (!task->src_iovs) {
		fprintf(stderr, "cannot allocated task->src_iovs fot task=%p\n", task);
		return -ENOMEM;
	}

	task->src = spdk_dma_zmalloc(MAX_XFER_SIZE, 0, NULL);
	memset(task->src, DATA_PATTERN, MAX_XFER_SIZE);

	if (g_workload_selection == SPDK_ACCEL_OPC_COPY_CRC32C ||
	    g_workload_selection == SPDK_ACCEL_OPC_COPY_CHECK_CRC32C) {
		task->dst_iovcnt = MAX_IOVS;
		task->dst_iovs = calloc(task->dst_iovcnt, sizeof(struct iovec));
		if (!task->dst_iovs) {
			fprintf(stderr, "cannot allocated task->src_iovs fot task=%p\n", task);
			return -ENOMEM;
		}
		task->dst = spdk_dma_zmalloc(MAX_XFER_SIZE, 0, NULL);
		if (task->dst == NULL) {
			fprintf(stderr, "Unable to alloc dst buffer\n");
			return -ENOMEM;
		}

		memset(task->dst, ~DATA_PATTERN, MAX_XFER_SIZE);
	}

	task->crc_dst = spdk_dma_zmalloc(sizeof(uint32_t), 0, NULL);
	if (task->crc_dst == NULL) {
		fprintf(stderr, "Unable to alloc crc_dst buffer\n");
		return -ENOMEM;
	}

	return 0;
}

static int
_get_crypto_task_data_bufs(struct ap_task *task)
{
	struct spdk_md5ctx md5ctx;
	uint32_t i;

	task->src_iovcnt = MAX_IOVS;
	task->src_iovs = calloc(task->src_iovcnt, sizeof(struct iovec));
	if (!task->src_iovs) {
		fprintf(stderr, "cannot allocated task->src_iovs fot task=%p\n", task);
		return -ENOMEM;
	}

	task->src = spdk_dma_zmalloc(MAX_XFER_SIZE, 0, NULL);
	for (i = 0; i < MAX_XFER_SIZE; i++) {
		((unsigned char *)task->src)[i] = (uint8_t)rand();
	}
	task->iv = (uint64_t)rand() * 1024;

	spdk_md5init(&md5ctx);
	spdk_md5update(&md5ctx, task->src, MAX_XFER_SIZE);
	spdk_md5final(task->src_md5, &md5ctx);

	if (!g_inplace) {
		task->dst_iovcnt = MAX_IOVS;
		task->dst_iovs = calloc(task->dst_iovcnt, sizeof(struct iovec));
		if (!task->dst_iovs) {
			fprintf(stderr, "cannot allocated task->src_iovs fot task=%p\n", task);
			return -ENOMEM;
		}
		task->dst = spdk_dma_zmalloc(MAX_XFER_SIZE, 0, NULL);
		if (task->dst == NULL) {
			fprintf(stderr, "Unable to alloc dst buffer\n");
			return -ENOMEM;
		}
	}

	return 0;
}


inline static struct ap_task *
_get_task(struct worker_thread *worker)
{
	struct ap_task *task;

	if (!TAILQ_EMPTY(&worker->tasks_pool)) {
		task = TAILQ_FIRST(&worker->tasks_pool);
		TAILQ_REMOVE(&worker->tasks_pool, task, link);
	} else {
		fprintf(stderr, "Unable to get ap_task\n");
		return NULL;
	}

	return task;
}

static uint32_t
set_iov(void *base_addr, const uint32_t *chunks, struct iovec *iovs, size_t *length)
{
	void *addr = base_addr;
	struct iovec *iov = iovs;
	size_t len = 0;
	int i;

	for (i = 0; (i < MAX_IOVS && chunks[i] != 0); i++) {
		iov->iov_base = addr;
		iov->iov_len = chunks[i];

		len += chunks[i];
		addr += chunks[i];
		iov++;
	}

	*length = len;

	return i;
}

static size_t
set_src_iov(struct ap_task *task, bool fill)
{
	size_t len = 0;

	task->src_iovcnt = set_iov(task->src, task->test->src, task->src_iovs, &len);
	if (fill) {
		memset(task->src, DATA_PATTERN, len);
	}

	return len;
}

static void
set_dst_iov(struct ap_task *task, bool fill)
{
	size_t len = 0;

	task->dst_iovcnt = set_iov(task->dst, task->test->dst, task->dst_iovs, &len);
	if (fill) {
		memset(task->dst, DATA_PATTERN, len);
	}
}

/* Submit one operation using the same ap task that just completed. */
static void
_submit_single(struct worker_thread *worker, struct ap_task *task)
{
	int rc = 0;
	struct spdk_accel_sequence *seq = NULL;
	spdk_accel_completion_cb cb = NULL;
	size_t len;

	assert(worker);

	switch (worker->workload) {
	case SPDK_ACCEL_OPC_CRC32C:
		task->test = &ap_tests[task->test_idx];
		set_src_iov(task, true);

		task->test_idx++;
		if (task->test_idx >= (int)SPDK_COUNTOF(ap_tests)) {
			task->test_idx = 0;
		}
		cb = accel_done;
		rc = spdk_accel_append_crc32c(&seq, worker->ch, task->crc_dst, task->src_iovs, task->src_iovcnt,
					      NULL,
					      NULL, g_crc32c_seed, NULL, NULL);
		break;
	case SPDK_ACCEL_OPC_COPY_CRC32C:
		task->test = &ap_tests[task->test_idx];
		set_src_iov(task, true);
		set_dst_iov(task, true);

		task->test_idx++;
		if (task->test_idx >= (int)SPDK_COUNTOF(ap_tests)) {
			task->test_idx = 0;
		}

		rc = spdk_accel_append_copy_crc32c(&seq, worker->ch, task->crc_dst, task->dst_iovs,
						   task->dst_iovcnt,
						   NULL, NULL, task->src_iovs, task->src_iovcnt, NULL, NULL,
						   g_crc32c_seed, NULL, NULL);
		cb = accel_done;
		break;
	case SPDK_ACCEL_OPC_CHECK_CRC32C:
		task->test = &ap_tests[task->test_idx];
		set_src_iov(task, true);
		*task->crc_dst = spdk_crc32c_iov_update(task->src_iovs, task->src_iovcnt, ~g_crc32c_seed);

		if (g_crc_error) {
			*task->crc_dst ^= 1;
		}

		task->test_idx++;
		if (task->test_idx >= (int)SPDK_COUNTOF(ap_tests)) {
			task->test_idx = 0;
		}
		cb = accel_done;
		rc = spdk_accel_append_check_crc32c(&seq, worker->ch, task->crc_dst, task->src_iovs,
						    task->src_iovcnt,
						    NULL, NULL, g_crc32c_seed, NULL, NULL);
		break;
	case SPDK_ACCEL_OPC_COPY_CHECK_CRC32C:
		task->test = &ap_tests[task->test_idx];
		set_src_iov(task, true);
		set_dst_iov(task, true);
		*task->crc_dst = spdk_crc32c_iov_update(task->src_iovs, task->src_iovcnt, ~g_crc32c_seed);

		if (g_crc_error) {
			*task->crc_dst ^= 1;
		}

		task->test_idx++;
		if (task->test_idx >= (int)SPDK_COUNTOF(ap_tests)) {
			task->test_idx = 0;
		}

		rc = spdk_accel_append_copy_check_crc32c(&seq, worker->ch, task->crc_dst,
				task->dst_iovs, task->dst_iovcnt, NULL, NULL,
				task->src_iovs, task->src_iovcnt, NULL, NULL,
				g_crc32c_seed, NULL, NULL);
		cb = accel_done;
		break;
	case SPDK_ACCEL_OPC_ENCRYPT:
		if (task->test_idx < (int)(SPDK_COUNTOF(ap_tests))) {
			task->test = &ap_tests[task->test_idx];
		} else {
			if (g_block_size == 512) {
				task->test = &ap_tests_crypto_bs_512[task->test_idx - (int)SPDK_COUNTOF(ap_tests)];
			} else {
				assert(g_block_size == 4096);
				task->test = &ap_tests_crypto_bs_4096[task->test_idx - (int)SPDK_COUNTOF(ap_tests)];
			}
		}
		len = set_src_iov(task, false);
		if (!g_inplace) {
			set_dst_iov(task, false);
		}
		task->test_idx++;
		if (task->test_idx >= (int)(SPDK_COUNTOF(ap_tests) + SPDK_COUNTOF(ap_tests_crypto_bs_512))) {
			task->test_idx = 0;
		}
		if (len % g_block_size != 0) {
			/* Common tests may have iov len which is not a multiple of block size, skip such test */
			assert(task->test_idx <= (int)(SPDK_COUNTOF(ap_tests)));
			_submit_single(worker, task);
			return;
		}

		rc = spdk_accel_append_encrypt(&seq, worker->ch, g_crypto_key,
					       g_inplace ? task->src_iovs : task->dst_iovs, g_inplace ? task->src_iovcnt : task->dst_iovcnt, NULL,
					       NULL,
					       task->src_iovs, task->src_iovcnt, NULL, NULL,
					       task->iv, g_block_size, NULL, NULL, NULL);
		cb = encrypt_done;
		break;
	default:
		assert(false);
		break;

	}

	if (rc) {
		accel_done(task, rc);
	} else {
		worker->current_queue_depth++;
		spdk_accel_sequence_finish(seq, cb, task);
	}
}

static void
_free_task_buffers(struct ap_task *task)
{
	if (task->dst_iovs) {
		free(task->dst_iovs);
	}
	if (task->src_iovs) {
		free(task->src_iovs);
	}

	spdk_dma_free(task->src);
	spdk_dma_free(task->dst);
	spdk_dma_free(task->crc_dst);
}

static int _worker_stop(void *arg);

static void
accel_done(void *arg1, int status)
{
	struct spdk_md5ctx md5ctx;
	uint8_t src_md5[SPDK_MD5DIGEST_LEN];
	struct ap_task *task = arg1;
	struct worker_thread *worker = task->worker;
	uint32_t sw_crc32c;
	size_t src_len;
	size_t dst_len;
	uint32_t i;

	assert(worker);
	assert(worker->current_queue_depth > 0);

	if (status == 0) {
		switch (worker->workload) {
		case SPDK_ACCEL_OPC_COPY_CRC32C:
			sw_crc32c = spdk_crc32c_iov_update(task->src_iovs, task->src_iovcnt, ~g_crc32c_seed);
			if (*task->crc_dst != sw_crc32c) {
				SPDK_NOTICELOG("CRC-32C miscompare: actual 0x%x, expected 0x%x\n", *task->crc_dst,
					       sw_crc32c);
				worker->xfer_failed++;
			}

			src_len = 0;
			for (i = 0; i < task->src_iovcnt; i++) {
				src_len += task->src_iovs[i].iov_len;
			}
			dst_len = 0;
			for (i = 0; i < task->dst_iovcnt; i++) {
				dst_len += task->dst_iovs[i].iov_len;
			}
			if (src_len != dst_len || memcmp(task->dst, task->src, dst_len)) {
				SPDK_NOTICELOG("Data miscompare\n");
				worker->xfer_failed++;
			}
			break;
		case SPDK_ACCEL_OPC_COPY_CHECK_CRC32C:
			if (g_crc_error) {
				SPDK_NOTICELOG("CHECK_CRC32 didn't fail on error injected\n");
				worker->xfer_failed++;
				break;
			}

			src_len = 0;
			for (i = 0; i < task->src_iovcnt; i++) {
				src_len += task->src_iovs[i].iov_len;
			}
			dst_len = 0;
			for (i = 0; i < task->dst_iovcnt; i++) {
				dst_len += task->dst_iovs[i].iov_len;
			}
			if (src_len != dst_len || memcmp(task->dst, task->src, dst_len)) {
				SPDK_NOTICELOG("Data miscompare\n");
				worker->xfer_failed++;
			}
			break;
		case SPDK_ACCEL_OPC_CRC32C:
			sw_crc32c = spdk_crc32c_iov_update(task->src_iovs, task->src_iovcnt, ~g_crc32c_seed);
			if (*task->crc_dst != sw_crc32c) {
				SPDK_NOTICELOG("CRC-32C miscompare: actual 0x%x, expected 0x%x\n", *task->crc_dst,
					       sw_crc32c);
				worker->xfer_failed++;
			}
			break;
		case SPDK_ACCEL_OPC_CHECK_CRC32C:
			if (g_crc_error) {
				SPDK_NOTICELOG("CHECK_CRC32 didn't fail on error injected\n");
				worker->xfer_failed++;
			}
			break;
		case SPDK_ACCEL_OPC_ENCRYPT:
			if (worker->is_draining) {
				break;
			}
			/* encrypt->decrypt is completed, src_iovs must contain original pattern */
			spdk_md5init(&md5ctx);
			spdk_md5update(&md5ctx, task->src, MAX_XFER_SIZE);
			spdk_md5final(src_md5, &md5ctx);
			if (memcmp(task->src_md5, src_md5, SPDK_MD5DIGEST_LEN) != 0) {
				SPDK_ERRLOG("Data corruption after decryption, src 8 bytes %"PRIx64"\n", *(uint64_t *)task->src);
				status = -EIO;
			}
			task->iv = (uint64_t)rand();
			break;
		default:
			assert(false);
			break;
		}
	} else {
		switch (worker->workload) {
		case SPDK_ACCEL_OPC_COPY_CHECK_CRC32C:
			if (g_crc_error) {
				/* Task is expected to fail */
				status = 0;
			}

			/* Check that copy was done */
			src_len = 0;
			for (i = 0; i < task->src_iovcnt; i++) {
				src_len += task->src_iovs[i].iov_len;
			}
			dst_len = 0;
			for (i = 0; i < task->dst_iovcnt; i++) {
				dst_len += task->dst_iovs[i].iov_len;
			}
			if (src_len != dst_len || memcmp(task->dst, task->src, dst_len)) {
				SPDK_NOTICELOG("Data miscompare\n");
				worker->xfer_failed++;
			}
			break;
		case SPDK_ACCEL_OPC_CHECK_CRC32C:
			if (g_crc_error) {
				/* Task is expected to fail */
				status = 0;
			}
			break;
		default:
			break;
		}
	}

	if (status) {
		worker->xfer_failed++;
	}

	worker->xfer_completed++;
	worker->current_queue_depth--;

	if (!worker->is_draining && status == 0) {
		TAILQ_INSERT_TAIL(&worker->tasks_pool, task, link);
		task = _get_task(worker);
		_submit_single(worker, task);
	} else {
		TAILQ_INSERT_TAIL(&worker->tasks_pool, task, link);
	}
}

static void
encrypt_done(void *arg1, int status)
{
	struct ap_task *task = arg1;
	struct worker_thread *worker = task->worker;
	struct spdk_accel_sequence *seq = NULL;
	int rc;

	assert(worker);

	if (worker->is_draining || status) {
		accel_done(arg1, status);
		return;
	}

	rc = spdk_accel_append_decrypt(&seq, worker->ch, g_crypto_key,
				       task->src_iovs, task->src_iovcnt, NULL, NULL,
				       g_inplace ? task->src_iovs : task->dst_iovs, g_inplace ? task->src_iovcnt : task->dst_iovcnt, NULL,
				       NULL,
				       task->iv, g_block_size, NULL, NULL, NULL);
	if (rc) {
		accel_done(arg1, rc);
	}

	spdk_accel_sequence_finish(seq, accel_done, task);
}


static int
dump_result(void)
{
	uint64_t total_completed = 0;
	uint64_t total_failed = 0;
	uint64_t total_miscompared = 0;
	uint64_t total_xfer_per_sec;
	struct worker_thread *worker = g_workers;

	printf("\nCore,Thread   Transfers     Failed     Miscompares\n");
	printf("------------------------------------------------------------------------\n");
	while (worker != NULL) {

		uint64_t xfer_per_sec = worker->xfer_completed / g_time_in_sec;

		total_completed += worker->xfer_completed;
		total_failed += worker->xfer_failed;
		total_miscompared += worker->injected_miscompares;

		if (xfer_per_sec) {
			printf("%u,%u%17" PRIu64 "/s%9" PRIu64 " %11" PRIu64 "\n",
			       worker->display.core, worker->display.thread, xfer_per_sec,
			       worker->xfer_failed, worker->injected_miscompares);
		}

		worker = worker->next;
	}

	total_xfer_per_sec = total_completed / g_time_in_sec;

	printf("=========================================================================\n");
	printf("Total:%15" PRIu64 "/s%9" PRIu64 " %11" PRIu64"\n\n",
	       total_xfer_per_sec, total_failed, total_miscompared);

	return total_failed ? 1 : 0;
}

static inline void
_free_task_buffers_in_pool(struct worker_thread *worker)
{
	struct ap_task *task;

	assert(worker);
	while ((task = TAILQ_FIRST(&worker->tasks_pool))) {
		TAILQ_REMOVE(&worker->tasks_pool, task, link);
		_free_task_buffers(task);
	}
}

static int
_check_draining(void *arg)
{
	struct worker_thread *worker = arg;

	assert(worker);

	if (worker->current_queue_depth == 0) {
		_free_task_buffers_in_pool(worker);
		spdk_poller_unregister(&worker->is_draining_poller);
		unregister_worker(worker);
	}

	return SPDK_POLLER_BUSY;
}

static int
_worker_stop(void *arg)
{
	struct worker_thread *worker = arg;

	assert(worker);

	spdk_poller_unregister(&worker->stop_poller);

	/* now let the worker drain and check it's outstanding IO with a poller */
	worker->is_draining = true;
	worker->is_draining_poller = SPDK_POLLER_REGISTER(_check_draining, worker, 0);

	return SPDK_POLLER_BUSY;
}

static void
_init_thread(void *arg1)
{
	struct worker_thread *worker;
	struct ap_task *task;
	int i, rc, num_tasks = g_allocate_depth;
	struct display_info *display = arg1;

	worker = calloc(1, sizeof(*worker));
	if (worker == NULL) {
		fprintf(stderr, "Unable to allocate worker\n");
		free(display);
		return;
	}

	worker->workload = g_workload_selection;
	if (worker->workload == SPDK_ACCEL_OPC_DECRYPT) {
		/* We run both encrypt and decrypt operations, encrypt first */
		worker->workload = SPDK_ACCEL_OPC_ENCRYPT;
	}
	worker->display.core = display->core;
	worker->display.thread = display->thread;
	free(display);
	worker->core = spdk_env_get_current_core();
	worker->thread = spdk_get_thread();
	pthread_mutex_lock(&g_workers_lock);
	g_num_workers++;
	worker->next = g_workers;
	g_workers = worker;
	pthread_mutex_unlock(&g_workers_lock);
	worker->ch = spdk_accel_get_io_channel();
	if (worker->ch == NULL) {
		fprintf(stderr, "Unable to get an accel channel\n");
		goto error;
	}

	TAILQ_INIT(&worker->tasks_pool);

	worker->task_base = calloc(num_tasks, sizeof(struct ap_task));
	if (worker->task_base == NULL) {
		fprintf(stderr, "Could not allocate task base.\n");
		goto error;
	}

	task = worker->task_base;
	for (i = 0; i < num_tasks; i++) {
		TAILQ_INSERT_TAIL(&worker->tasks_pool, task, link);
		task->worker = worker;
		switch (g_workload_selection) {
		case SPDK_ACCEL_OPC_CRC32C:
		case SPDK_ACCEL_OPC_COPY_CRC32C:
		case SPDK_ACCEL_OPC_CHECK_CRC32C:
		case SPDK_ACCEL_OPC_COPY_CHECK_CRC32C:
			rc = _get_crc_task_data_bufs(task);
			break;
		case SPDK_ACCEL_OPC_ENCRYPT:
		case SPDK_ACCEL_OPC_DECRYPT:
			rc = _get_crypto_task_data_bufs(task);
			break;
		default:
			SPDK_ERRLOG("Unexpected opcode %d\n", g_workload_selection);
			assert(0);
			break;
		}
		if (rc) {
			fprintf(stderr, "Unable to get data bufs\n");
			goto error;
		}
		task++;
	}

	/* Register a poller that will stop the worker at time elapsed */
	worker->stop_poller = SPDK_POLLER_REGISTER(_worker_stop, worker,
			      g_time_in_sec * 1000000ULL);

	/* Load up queue depth worth of operations. */
	for (i = 0; i < g_queue_depth; i++) {
		task = _get_task(worker);
		if (task == NULL) {
			goto error;
		}

		_submit_single(worker, task);
	}
	return;
error:

	_free_task_buffers_in_pool(worker);
	free(worker->task_base);
	spdk_app_stop(-1);
}

static void
accel_perf_prep(void *arg1)
{
	struct spdk_cpuset tmp_cpumask = {};
	char thread_name[32];
	uint32_t i;
	int j;
	struct spdk_thread *thread;
	struct display_info *display;

	g_tsc_rate = spdk_get_ticks_hz();
	g_tsc_end = spdk_get_ticks() + g_time_in_sec * g_tsc_rate;

	/* We have to verify parameters here since spdk_accel_crypto_key_get uses spdk_spinlock which depends on the
	 * thread library which initialized after app_start call */
	switch (g_workload_selection) {
	case SPDK_ACCEL_OPC_CRC32C:
	case SPDK_ACCEL_OPC_COPY_CRC32C:
	case SPDK_ACCEL_OPC_CHECK_CRC32C:
	case SPDK_ACCEL_OPC_COPY_CHECK_CRC32C:
		break;
	case SPDK_ACCEL_OPC_ENCRYPT:
	case SPDK_ACCEL_OPC_DECRYPT:
		srand(time(NULL));
		g_crypto_key = spdk_accel_crypto_key_get(g_crypto_key_name);
		if (g_crypto_key) {
			if (g_block_size != 512 && g_block_size != 4096) {
				SPDK_ERRLOG("Invalid block size %u\n", g_block_size);
			} else {
				break;
			}
		} else {
			SPDK_ERRLOG("Failed to get crypto key %s\n", g_crypto_key_name);
		}
	/* fallthrough */
	default:
		usage();
		g_rc = -1;
		return;
	}

	dump_user_config();

	printf("Running for %d seconds...\n", g_time_in_sec);
	fflush(stdout);

	/* Create worker threads for each core that was specified. */
	SPDK_ENV_FOREACH_CORE(i) {
		for (j = 0; j < g_threads_per_core; j++) {
			snprintf(thread_name, sizeof(thread_name), "ap_worker_%u_%u", i, j);
			spdk_cpuset_zero(&tmp_cpumask);
			spdk_cpuset_set_cpu(&tmp_cpumask, i, true);
			thread = spdk_thread_create(thread_name, &tmp_cpumask);
			display = calloc(1, sizeof(*display));
			if (display == NULL) {
				fprintf(stderr, "Unable to allocate memory\n");
				spdk_app_stop(-1);
				return;
			}
			display->core = i;
			display->thread = j;
			spdk_thread_send_msg(thread, _init_thread, display);
		}
	}
}

int
main(int argc, char **argv)
{
	struct worker_thread *worker, *tmp;

	pthread_mutex_init(&g_workers_lock, NULL);
	spdk_app_opts_init(&g_opts, sizeof(g_opts));
	g_opts.name = "accel_test";
	g_opts.reactor_mask = "0x1";
	if (spdk_app_parse_args(argc, argv, &g_opts, "a:b:fq:I:K:t:T:w:", NULL, parse_args,
				usage) != SPDK_APP_PARSE_ARGS_SUCCESS) {
		g_rc = -1;
		goto cleanup;
	}

	if (g_allocate_depth > 0 && g_queue_depth > g_allocate_depth) {
		fprintf(stdout, "allocate depth must be at least as big as queue depth\n");
		usage();
		g_rc = -1;
		goto cleanup;
	}

	if (g_allocate_depth == 0) {
		g_allocate_depth = g_queue_depth;
	}

	g_rc = spdk_app_start(&g_opts, accel_perf_prep, NULL);
	if (g_rc) {
		SPDK_ERRLOG("ERROR starting application\n");
	}

	pthread_mutex_destroy(&g_workers_lock);

	worker = g_workers;
	while (worker) {
		tmp = worker->next;
		free(worker);
		worker = tmp;
	}
cleanup:
	spdk_app_fini();
	return g_rc;
}
