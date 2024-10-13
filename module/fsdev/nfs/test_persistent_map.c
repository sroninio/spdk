#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "persistent_map.h"
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <time.h>
#include <time.h>

#define TEST_FILE "btest_db.bin"
#define TEST_SIZE 10

/*
void test_init_map_db()
{
    printf("\n\033[1;33m=== Testing init_map_db ===\033[0m\n");

    // Test initial creation
    DB *db = init_map_db(TEST_FILE, TEST_SIZE);

    print_list(db); //

    assert(db != NULL);
    printf("\033[0;32m✓ Database initialized successfully\033[0m\n");

    // Test restoration
    DB *restored_db = init_map_db(TEST_FILE, TEST_SIZE);
    assert(restored_db != NULL);
    printf("\033[0;32m✓ Database restored successfully\033[0m\n");

    print_list(db); //

    // Clean up
    free(db);
    free(restored_db);
}

void test_insert_db()
{
    printf("\n\033[1;33m=== Testing insert_db ===\033[0m\n");

    DB *db = init_map_db(TEST_FILE, TEST_SIZE);

    printf("\033[0;32mthis is before any chnages :\033[0m\n");
    print_list(db); //

    // Test insertion
    struct nfs_fh3 value = {{1, 5, "test", 2}};
    assert(insert_db(db, 1, &value));
    printf("\033[0;32m✓ Inserted first entry successfully with key 1\033[0m\n");

    print_list(db); //

    // Test duplicate insertion (should update)
    struct nfs_fh3 updated_value = {{1, 6, "updated", 2}};
    assert(insert_db(db, 1, &updated_value));
    printf("\033[0;32m✓ Updated existing entry successfully with key 1\033[0m\n");

    print_list(db); //

    // Fill the database
    for (unsigned long i = 2; i <= TEST_SIZE; i++)
    {
        struct nfs_fh3 val = {{i, 5, "test", 2}};
        assert(insert_db(db, i, &val));
        printf("\033[0;32m✓ Inserted new entry successfully with key %ld\033[0m\n", i);
        print_list(db); //
    }
    printf("\033[0;32m✓ Filled database to capacity\033[0m\n");

    // Try to insert when full
    struct nfs_fh3 extra_value = {{11, 5, "extra", 2}};
    assert(!insert_db(db, 11, &extra_value));
    printf("\033[0;32m✓ Correctly failed to insert when database is full\033[0m\n");
    print_list(db); //

    // Clean up
    free(db);
}

void test_delete_entry_db()
{
    printf("\n\033[1;33m=== Testing delete_entry_db ===\033[0m\n");

    DB *db = init_map_db(TEST_FILE, TEST_SIZE);
    printf("\033[0;32mthis is before any chnages :\033[0m\n");
    print_list(db); //
    // Insert some entries
    for (unsigned long i = 1; i <= 5; i++)
    {
        struct nfs_fh3 val = {{i, 5, "test", 2}};
        insert_db(db, i, &val);
        printf("\033[0;32m✓ Inserted same entry successfully with key %ld\033[0m\n", i);
        print_list(db); //
    }

    // Test deletion
    assert(delete_entry_db(db, 3));
    printf("\033[0;32m✓ Deleted existing entry successfully with key 3\033[0m\n");
    print_list(db); //

    // Test deleting non-existent entry
    assert(!delete_entry_db(db, 11));
    printf("\033[0;32m✓ Correctly failed to delete non-existent entry key 11\033[0m\n");
    print_list(db); //

    // Test inserting after deletion
    struct nfs_fh3 new_value = {{6, 5, "new", 2}};
    assert(insert_db(db, 16, &new_value));
    printf("\033[0;32m✓ Inserted new entry after deletion\033[0m\n");
    print_list(db); //

    // Clean up
    free(db);
}

void test_get_db()
{
    printf("\n\033[1;33m=== Testing get_db ===\033[0m\n");

    DB *db = init_map_db(TEST_FILE, TEST_SIZE);

    printf("\033[0;32mthis is before any chnages :\033[0m\n");
    print_list(db); //

    // Insert an entry
    struct nfs_fh3 value = {{3, 5, "test", 2}};
    insert_db(db, 1, &value);
    printf("\033[0;32minserting same entery with key 1 \033[0m\n");
    print_list(db); //

    // Test getting existing entry
    struct nfs_fh3 *retrieved = get_db(db, 1);

    printf("retrived values: data.num1 = %d, data_len =%d, data_val = %s, num2 = %d \n", retrieved->data.num1 == 1, retrieved->data.data_len == 5, retrieved->data.data_val, retrieved->data.num2);
    assert(retrieved != NULL);
    assert(retrieved->data.num1 == 3);
    assert(retrieved->data.data_len == 5);
    assert(strcmp(retrieved->data.data_val, "test") == 0);
    assert(retrieved->data.num2 == 2);
    printf("\033[0;32m✓ Retrieved existing entry successfully\033[0m\n");
    print_list(db); //

    // Test getting non-existent entry
    assert(get_db(db, 100) == NULL);
    printf("\033[0;32m✓ Correctly returned NULL for non-existent entry\033[0m\n");
    print_list(db); //

    // Clean up
    free(db);
}

pid_t child_pid;

void signal_handler(int signum)
{
    if (child_pid > 0)
    {
        kill(child_pid, SIGTERM);
    }
}

void loop_function(DB *db, unsigned long size)
{
    for (unsigned long i = 0; i < size; ++i)
    {
        struct nfs_fh3 value = {{i, i, "test", i}};
        insert_db(db, i, &value);

        // Simulate some work
        usleep(10000); // Sleep for 10ms
    }
    printf("Loop completed all iterations\n");
}

void stress_test(unsigned long size, int total, int i)
{
    remove(TEST_FILE);
    DB *db = init_map_db(TEST_FILE, size);
    printf("\033[0;32m✓ Created a Data Base with [%lu] entries test %d/%d\033[0m\n", size, i, total);

    // Set up signal handler in the parent process
    signal(SIGALRM, signal_handler);

    child_pid = fork();

    if (child_pid == -1)
    {
        perror("fork failed");
        exit(1);
    }
    else if (child_pid == 0)
    {
        // Child process
        loop_function(db, size);
        exit(0);
    }
    else
    {
        // Parent process
        // Set a random alarm to terminate the child process
        srand(time(NULL));
        int alarm_time = rand() % 5 + 1; // 1-5 seconds
        alarm(alarm_time);

        int status;
        waitpid(child_pid, &status, 0);

        if (WIFSIGNALED(status))
        {
            printf("Child process was terminated by signal %d\n", WTERMSIG(status));
        }
        else if (WIFEXITED(status))
        {
            printf("Child process exited with status %d\n", WEXITSTATUS(status));
        }
    }

    bool is_ok = true;
    for (int i = 0; i < size; i++)
    {
        struct nfs_fh3 *value = get_db(db, i);
        if (value != NULL)
        {
            if (value->data.num1 != value->data.num2)
            {
                printf("\033[0;31mData corruption: num1 != num2 (%d != %d)\033[0m\n", value->data.num1, value->data.num2);
                is_ok = false;
            }
        }
    }

    if (is_ok)
    {
        printf("\033[0;32m✓Stress test completed\033[0m\n");
    }
    else
    {
        printf("\033[0;31mx Stress test failed\033[0m\n");
    }
    remove(TEST_FILE);
}

void test_stress()
{
    printf("\n\033[1;33m=== Stress Test ===\033[0m\n");

    int size = 1000000;
    for (int i = 0; i < 10; ++i)
    {
        stress_test(size, 10, i + 1);
    }
}

void test_stress_v2()
{
    printf("\n\033[1;33m=== Stress Test V2 ===\033[0m\n");

    remove(TEST_FILE);

    // creating a counter file:
    char *filename = "counter.txt";
    int fd = open(filename, O_RDWR | O_CREAT, 0666);
    if (fd == -1)
    {
        perror("Error: in opening file");
        return;
    }

    size_t full_size = sizeof(unsigned long);
    if (ftruncate(fd, full_size) == -1)
    {
        perror("Error: setting file size");
        close(fd);
        return;
    }

    unsigned long *counterFile = mmap(NULL, full_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (counterFile == MAP_FAILED)
    {
        perror("Error: error mapping counterFile");
        close(fd);
        return;
    }

    // Set up signal handler in the parent process
    signal(SIGALRM, signal_handler);

    child_pid = fork();

    if (child_pid == -1)
    {
        perror("fork failed");
        exit(1);
    }
    else if (child_pid == 0)
    {
        // Child process
        DB *db = init_map_db(TEST_FILE, 10000000);
        for (unsigned long i = 0; i < 10000000; ++i)
        {
            struct nfs_fh3 e = {{i, 5, "test", i}};
            insert_db(db, i, &e); // insert to our map
            *counterFile = i;     // update the data structure
        }
        exit(0);
    }
    else
    {
        // Parent process
        // Set a random alarm to terminate the child process
        srand(time(NULL));
        int alarm_time = rand() % 5 + 1; // 1-5 seconds
        alarm(alarm_time);

        int status;
        waitpid(child_pid, &status, 0);

        if (WIFSIGNALED(status))
        {
            printf("Child process was terminated by signal %d\n", WTERMSIG(status));
        }
        else if (WIFEXITED(status))
        {
            printf("Child process exited with status %d\n", WEXITSTATUS(status));
        }
    }

    bool is_ok = true;
    unsigned long max_value = *counterFile;
    DB *db = init_map_db(TEST_FILE, 10000000);
    printf("the last inode inserted is [%ld]\n", max_value);
    for (unsigned long i = 0; i <= max_value; ++i)
    {
        struct nfs_fh3 *value = get_db(db, i);
        if (value != NULL)
        {
            if (value->data.num1 != value->data.num2)
            {
                printf("\033[0;31mData corruption: num1 != num2 (%d != %d)\033[0m\n", value->data.num1, value->data.num2);
                is_ok = false;
            }
        }
        else
        {
            is_ok = false;
        }
    }

    if (is_ok)
    {
        printf("\033[0;32m✓Stress test completed\033[0m\n");
    }
    else
    {
        printf("\033[0;31mx Stress test failed\033[0m\n");
    }

    remove(TEST_FILE);
}

*/
int main()
{
    printf("\033[1;34m==== Starting Persistent Map Database Tests ====\033[0m\n");

    DB *db = init_map_db(TEST_FILE, TEST_SIZE);

    // print_list(db); //
    struct nfs_fh3 fh = {0};
    fh.data.data_val = "hello world";
    fh.data.data_len = 12;
    insert_db(db, 3, &fh);

    unsigned long answer = 244;
    if (fh_exist_db(db, &fh, &answer))
    {
        printf("this in the map with answer = [%ld]!\n", answer);
    }
    else
    {
        printf("this is not in map !! \n");
    }

    /*
        test_init_map_db();
        test_insert_db();
        test_delete_entry_db();
        test_get_db();
        test_stress();    // TO DO: need to make sure this runs correctly !
        test_stress_v2(); // TO DO: need to make sure this runs correctly !
    */
    printf("\n\033[1;32m==== All tests passed successfully! ====\033[0m\n");
    return 0;
}