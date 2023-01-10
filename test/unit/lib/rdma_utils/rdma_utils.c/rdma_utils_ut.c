/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES.
 *   All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk_internal/cunit.h"
#include "spdk_internal/mock.h"
#include "common/lib/test_env.c"
#include "rdma_utils/rdma_utils.c"

DEFINE_STUB(spdk_mem_map_alloc, struct spdk_mem_map *, (uint64_t default_translation,
		const struct spdk_mem_map_ops *ops, void *cb_ctx), NULL);
DEFINE_STUB_V(spdk_mem_map_free, (struct spdk_mem_map **pmap));
DEFINE_STUB(spdk_mem_map_set_translation, int, (struct spdk_mem_map *map, uint64_t vaddr,
		uint64_t size, uint64_t translation), 0);
DEFINE_STUB(spdk_mem_map_clear_translation, int, (struct spdk_mem_map *map, uint64_t vaddr,
		uint64_t size), 0);
DEFINE_STUB(spdk_mem_map_translate, uint64_t, (const struct spdk_mem_map *map, uint64_t vaddr,
		uint64_t *size), 0);
DEFINE_RETURN_MOCK(spdk_memory_domain_create, int);
int
spdk_memory_domain_create(struct spdk_memory_domain **domain, enum spdk_dma_device_type type,
			  struct spdk_memory_domain_ctx *ctx, const char *id)
{
	static struct spdk_memory_domain *__dma_dev = (struct spdk_memory_domain *)0xdeaddead;

	HANDLE_RETURN_MOCK(spdk_memory_domain_create);

	*domain = __dma_dev;

	return 0;
}
DEFINE_STUB_V(spdk_memory_domain_destroy, (struct spdk_memory_domain *device));

struct ut_rdma_device {
	struct ibv_context		*context;
	bool				removed;
	TAILQ_ENTRY(ut_rdma_device)	tailq;
};

static TAILQ_HEAD(, ut_rdma_device) g_ut_dev_list = TAILQ_HEAD_INITIALIZER(g_ut_dev_list);

struct ibv_context **
rdma_get_devices(int *num_devices)
{
	struct ibv_context **ctx_list;
	struct ut_rdma_device *ut_dev;
	int num_ut_devs = 0;
	int i = 0;

	TAILQ_FOREACH(ut_dev, &g_ut_dev_list, tailq) {
		if (!ut_dev->removed) {
			num_ut_devs++;
		}
	}

	ctx_list = malloc(sizeof(*ctx_list) * (num_ut_devs + 1));
	SPDK_CU_ASSERT_FATAL(ctx_list);

	TAILQ_FOREACH(ut_dev, &g_ut_dev_list, tailq) {
		if (!ut_dev->removed) {
			ctx_list[i++] = ut_dev->context;
		}
	}
	ctx_list[i] = NULL;

	if (num_devices) {
		*num_devices = num_ut_devs;
	}

	return ctx_list;
}

void
rdma_free_devices(struct ibv_context **list)
{
	free(list);
}

struct ibv_pd *
ibv_alloc_pd(struct ibv_context *context)
{
	struct ibv_pd *pd;
	struct ut_rdma_device *ut_dev;

	TAILQ_FOREACH(ut_dev, &g_ut_dev_list, tailq) {
		if (ut_dev->context == context && !ut_dev->removed) {
			break;
		}
	}

	if (!ut_dev) {
		return NULL;
	}

	pd = calloc(1, sizeof(*pd));
	SPDK_CU_ASSERT_FATAL(pd);

	pd->context = context;

	return pd;
}

int
ibv_dealloc_pd(struct ibv_pd *pd)
{
	free(pd);

	return 0;
}

static struct ut_rdma_device *
ut_rdma_add_dev(struct ibv_context *context)
{
	struct ut_rdma_device *ut_dev;

	ut_dev = calloc(1, sizeof(*ut_dev));
	if (!ut_dev) {
		return NULL;
	}

	ut_dev->context = context;
	TAILQ_INSERT_TAIL(&g_ut_dev_list, ut_dev, tailq);

	return ut_dev;
}

static void
ut_rdma_remove_dev(struct ut_rdma_device *ut_dev)
{
	TAILQ_REMOVE(&g_ut_dev_list, ut_dev, tailq);
	free(ut_dev);
}

static struct rdma_utils_device *
_rdma_get_dev(struct ibv_context *context)
{
	struct rdma_utils_device *dev = NULL;

	TAILQ_FOREACH(dev, &g_dev_list, tailq) {
		if (dev->context == context) {
			break;
		}
	}

	return dev;
}

static void
test_spdk_rdma_pd(void)
{
	struct ut_rdma_device *ut_dev0, *ut_dev1, *ut_dev2;
	struct ibv_pd *pd1, *pd1_1, *pd2;

	ut_dev0 = ut_rdma_add_dev((struct ibv_context *)0xface);
	SPDK_CU_ASSERT_FATAL(ut_dev0 != NULL);

	ut_dev1 = ut_rdma_add_dev((struct ibv_context *)0xc0ffee);
	SPDK_CU_ASSERT_FATAL(ut_dev1 != NULL);

	ut_dev2 = ut_rdma_add_dev((struct ibv_context *)0xf00d);
	SPDK_CU_ASSERT_FATAL(ut_dev2 != NULL);

	/* There are ut_dev0 and ut_dev1. */
	ut_dev2->removed = true;

	/* Call spdk_rdma_utils_get_pd() to non-existent ut_dev2. */
	pd2 = spdk_rdma_utils_get_pd(ut_dev2->context);

	/* Then, spdk_rdma_utils_get_pd() should return NULL and g_dev_list should have dev0 and dev1. */
	CU_ASSERT(pd2 == NULL);
	CU_ASSERT(_rdma_get_dev(ut_dev0->context) != NULL);
	CU_ASSERT(_rdma_get_dev(ut_dev1->context) != NULL);
	CU_ASSERT(_rdma_get_dev(ut_dev2->context) == NULL);

	/* Remove ut_dev0 and add ut_dev2. */
	ut_dev0->removed = true;
	ut_dev2->removed = false;

	/* Call spdk_rdma_utils_get_pd() to ut_dev1. */
	pd1 = spdk_rdma_utils_get_pd(ut_dev1->context);

	/* Then, spdk_rdma_utils_get_pd() should return pd1 and g_dev_list should have dev1 and dev2. */
	CU_ASSERT(pd1 != NULL);
	CU_ASSERT(_rdma_get_dev(ut_dev0->context) == NULL);
	CU_ASSERT(_rdma_get_dev(ut_dev1->context) != NULL);
	CU_ASSERT(_rdma_get_dev(ut_dev2->context) != NULL);

	/* Remove ut_dev1. */
	ut_dev1->removed = true;

	/* Call spdk_rdma_utils_get_pd() again to ut_dev1 which does not exist anymore. */
	pd1_1 = spdk_rdma_utils_get_pd(ut_dev1->context);

	/* Then, spdk_rdma_utils_get_pd() should return NULL and g_dev_list should still have dev1. */
	CU_ASSERT(pd1_1 == NULL);
	CU_ASSERT(_rdma_get_dev(ut_dev0->context) == NULL);
	CU_ASSERT(_rdma_get_dev(ut_dev1->context) != NULL);
	CU_ASSERT(_rdma_get_dev(ut_dev2->context) != NULL);

	/* Call spdk_rdma_put_pd() to pd1. */
	spdk_rdma_utils_put_pd(pd1);

	/* Then, dev1 should be removed from g_dev_list. */
	CU_ASSERT(_rdma_get_dev(ut_dev0->context) == NULL);
	CU_ASSERT(_rdma_get_dev(ut_dev1->context) == NULL);
	CU_ASSERT(_rdma_get_dev(ut_dev2->context) != NULL);

	/* Call spdk_rdma_utils_get_pd() to ut_dev2. */
	pd2 = spdk_rdma_utils_get_pd(ut_dev2->context);

	/* spdk_rdma_utils_get_pd() should succeed and g_dev_list should still have dev2
	 * even after spdk_rdma_put_pd() is called to pd2.
	 */
	CU_ASSERT(pd2 != NULL);

	spdk_rdma_utils_put_pd(pd2);

	CU_ASSERT(_rdma_get_dev(ut_dev0->context) == NULL);
	CU_ASSERT(_rdma_get_dev(ut_dev1->context) == NULL);
	CU_ASSERT(_rdma_get_dev(ut_dev2->context) != NULL);

	_rdma_utils_fini();

	ut_rdma_remove_dev(ut_dev0);
	ut_rdma_remove_dev(ut_dev1);
	ut_rdma_remove_dev(ut_dev2);
}

static void
test_spdk_rdma_utils_memory_domain(void)
{
	struct spdk_rdma_utils_memory_domain *domain_1 = NULL, *domain_2 = NULL, *domain_tmp;
	struct ibv_pd *pd_1 = (struct ibv_pd *)0x1, *pd_2 = (struct ibv_pd *)0x2;
	/* Counters below are used to check the number of created/destroyed rdma_dma_device objects.
	 * Since other unit tests may create dma_devices, we can't just check that the queue is empty or not */
	uint32_t dma_dev_count_start = 0, dma_dev_count = 0, dma_dev_count_end = 0;

	TAILQ_FOREACH(domain_tmp, &g_memory_domains, link) {
		dma_dev_count_start++;
	}

	/* spdk_memory_domain_create failed, expect fail */
	MOCK_SET(spdk_memory_domain_create, -1);
	domain_1 = spdk_rdma_utils_get_memory_domain(pd_1, SPDK_DMA_DEVICE_TYPE_RDMA);
	CU_ASSERT(domain_1 == NULL);
	MOCK_CLEAR(spdk_memory_domain_create);

	/* Normal scenario */
	domain_1 = spdk_rdma_utils_get_memory_domain(pd_1, SPDK_DMA_DEVICE_TYPE_RDMA);
	SPDK_CU_ASSERT_FATAL(domain_1 != NULL);
	CU_ASSERT(domain_1->domain != NULL);
	CU_ASSERT(domain_1->pd == pd_1);
	CU_ASSERT(domain_1->ref == 1);

	/* Request the same pd, ref counter increased */
	CU_ASSERT(spdk_rdma_utils_get_memory_domain(pd_1, SPDK_DMA_DEVICE_TYPE_RDMA) == domain_1);
	CU_ASSERT(domain_1->ref == 2);

	/* Request another pd */
	domain_2 = spdk_rdma_utils_get_memory_domain(pd_2, SPDK_DMA_DEVICE_TYPE_RDMA);
	SPDK_CU_ASSERT_FATAL(domain_2 != NULL);
	CU_ASSERT(domain_2->domain != NULL);
	CU_ASSERT(domain_2->pd == pd_2);
	CU_ASSERT(domain_2->ref == 1);

	TAILQ_FOREACH(domain_tmp, &g_memory_domains, link) {
		dma_dev_count++;
	}
	CU_ASSERT(dma_dev_count == dma_dev_count_start + 2);

	/* put domain_1, decrement refcount */
	spdk_rdma_utils_put_memory_domain(domain_1);

	/* Release both devices */
	CU_ASSERT(domain_2->ref == 1);
	spdk_rdma_utils_put_memory_domain(domain_1);
	spdk_rdma_utils_put_memory_domain(domain_2);

	TAILQ_FOREACH(domain_tmp, &g_memory_domains, link) {
		dma_dev_count_end++;
	}
	CU_ASSERT(dma_dev_count_start == dma_dev_count_end);
}


int
main(int argc, char **argv)
{
	CU_pSuite suite = NULL;
	unsigned int num_failures;

	CU_initialize_registry();

	suite = CU_add_suite("rdma_common", NULL, NULL);
	CU_ADD_TEST(suite, test_spdk_rdma_pd);
	CU_ADD_TEST(suite, test_spdk_rdma_utils_memory_domain);

	num_failures = spdk_ut_run_tests(argc, argv, NULL);
	CU_cleanup_registry();
	return num_failures;
}
