// test_persistent_map.c

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "persistent_map.h"

#define TEST_FILE "test_db.bin"
#define TEST_SIZE 10

void print_nfs_fh3(struct nfs_fh3 *fh)
{
    printf("NFS File Handle: len=%d, data=", fh->data.data_len);
    for (int i = 0; i < fh->data.data_len; i++)
    {
        printf("%02x", (unsigned char)fh->data.data_val[i]);
    }
    printf("\n");
}

void test_init_map_db()
{
    printf("Testing init_map_db...\n");

    MyMap fast_map = NULL;
    DBptr db = init_map_db(TEST_FILE, &fast_map, TEST_SIZE);

    assert(db != NULL);
    assert(fast_map != NULL);
    assert(db->header.size == TEST_SIZE);
    assert(db->header.magic == MAGIC_NUMBER);
    assert(db->header.head == 0);

    printf("init_map_db test passed.\n\n");
}

void test_insert_db()
{
    printf("Testing insert_db...\n");

    MyMap fast_map = NULL;
    DBptr db = init_map_db(TEST_FILE, &fast_map, TEST_SIZE);

    struct nfs_fh3 fh1 = {.data.data_len = 4, .data.data_val = "test"};
    struct nfs_fh3 fh2 = {.data.data_len = 5, .data.data_val = "hello"};

    assert(insert_db(db, fast_map, 1, &fh1));
    assert(insert_db(db, fast_map, 2, &fh2));

    struct nfs_fh3 *result1 = get_db(fast_map, 1);
    struct nfs_fh3 *result2 = get_db(fast_map, 2);

    assert(result1 != NULL);
    assert(result2 != NULL);
    assert(result1->data.data_len == 4);
    assert(strncmp(result1->data.data_val, "test", 4) == 0);
    assert(result2->data.data_len == 5);
    assert(strncmp(result2->data.data_val, "hello", 5) == 0);

    printf("insert_db test passed.\n\n");
}

void test_delete_entry_db()
{
    printf("Testing delete_entry_db...\n");

    MyMap fast_map = NULL;
    DBptr db = init_map_db(TEST_FILE, &fast_map, TEST_SIZE);

    struct nfs_fh3 fh = {.data.data_len = 4, .data.data_val = "test"};

    assert(insert_db(db, fast_map, 1, &fh));
    assert(get_db(fast_map, 1) != NULL);

    assert(delete_entry_db(db, fast_map, 1));
    assert(get_db(fast_map, 1) == NULL);

    // assert(!delete_entry_db(db, fast_map, 1)); // Trying to delete non-existent key

    printf("delete_entry_db test passed.\n\n");
}

void test_get_db()
{
    printf("Testing get_db...\n");

    MyMap fast_map = NULL;
    DBptr db = init_map_db(TEST_FILE, &fast_map, TEST_SIZE);

    struct nfs_fh3 fh = {.data.data_len = 4, .data.data_val = "test"};

    assert(insert_db(db, fast_map, 1, &fh));

    struct nfs_fh3 *result = get_db(fast_map, 1);
    assert(result != NULL);
    assert(result->data.data_len == 4);
    assert(strncmp(result->data.data_val, "test", 4) == 0);

    // assert(get_db(fast_map, 2) == NULL); // Non-existent key

    printf("get_db test passed.\n\n");
}

void test_full_map()
{
    printf("Testing full map scenario...\n");

    MyMap fast_map = NULL;
    DBptr db = init_map_db(TEST_FILE, &fast_map, 3); // Small size for testing
    printf("checkpoint1 \n");

    struct nfs_fh3 fh1 = {.data.data_len = 1, .data.data_val = "a"};
    struct nfs_fh3 fh2 = {.data.data_len = 1, .data.data_val = "b"};
    struct nfs_fh3 fh3 = {.data.data_len = 1, .data.data_val = "c"};
    struct nfs_fh3 fh4 = {.data.data_len = 1, .data.data_val = "d"};
    printf("checkpoint1 \n");

    assert(insert_db(db, fast_map, 1, &fh1));
    printf("checkpoint1 \n");
    assert(insert_db(db, fast_map, 2, &fh2));
    printf("checkpoint1 \n");

    assert(insert_db(db, fast_map, 3, &fh3));
    printf("checkpoint1 \n");

    assert(!insert_db(db, fast_map, 4, &fh4)); // Should fail, map is full
    printf("checkpoint1 \n");

    assert(delete_entry_db(db, fast_map, 2));
    assert(insert_db(db, fast_map, 4, &fh4)); // Should succeed now

    printf("Full map scenario test passed.\n\n");
}

void test_persistence()
{
    printf("Testing persistence...\n");

    {
        MyMap fast_map = NULL;
        DBptr db = init_map_db(TEST_FILE, &fast_map, TEST_SIZE);

        struct nfs_fh3 fh = {.data.data_len = 4, .data.data_val = "test"};
        assert(insert_db(db, fast_map, 1, &fh));

        // Simulate process crash by not properly closing the database
    }

    {
        MyMap fast_map = NULL;
        DBptr db = init_map_db(TEST_FILE, &fast_map, TEST_SIZE);

        struct nfs_fh3 *result = get_db(fast_map, 1);
        assert(result != NULL);
        assert(result->data.data_len == 4);
        assert(strncmp(result->data.data_val, "test", 4) == 0);
    }

    printf("Persistence test passed.\n\n");
}

int main()
{
    test_init_map_db();
    test_insert_db();
    test_delete_entry_db();
    test_get_db();
    test_full_map();
    test_persistence();

    printf("All tests passed successfully!\n");
    return 0;
}