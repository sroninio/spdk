#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <stdbool.h>
#include "mymap.h"
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"
#include "libnfs-raw-nfs.h"

#define MAGIC_NUMBER 0x12345678
#define MAP_MAX_SIZE 20

#define FILLED -2
#define END_OF_LIST -1
#define EMPTHY 0
#define NONE_ZERO_VALUE 17
#define ALL_FILLED -9

struct Header
{
    int start_index;
    int magic;
};

struct Entry
{
    unsigned long key;
    struct nfs_fh3 value;
};

/*
struct Data Base{
    struct Header my_header;
    struct Entry[];
}


- no need for atomic actions in assiging a value
- need to add flushing mechanism
- need to combine the two arrys into one !
- make the code more elegent

*/

/*  We are returning a pointer to the slow map, and assigining in the pointer given to us a fast map !! of whom the user should use */
void *init_map_db(const char *filename, void **fast_map)
{
    int fd = open(filename, O_RDWR | O_CREAT, 0666);
    if (fd == -1)
    {
        perror("Error opening file");
        return NULL;
    }

    size_t size = sizeof(struct Header) + MAP_MAX_SIZE * sizeof(struct Entry) + MAP_MAX_SIZE * sizeof(int);
    if (ftruncate(fd, size) == -1)
    {
        perror("Error setting file size");
        close(fd);
        return NULL;
    }

    void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED)
    {
        perror("Error mapping file");
        close(fd);
        return NULL;
    }

    struct Header *header = (struct Header *)addr;
    *fast_map = create_my_map();
    if (header->magic != MAGIC_NUMBER)
    {
        header->start_index = 0;
        int *free_list = (int *)((char *)addr + sizeof(struct Header) + MAP_MAX_SIZE * sizeof(struct Entry));
        for (int i = 0; i < MAP_MAX_SIZE - 1; i++)
        {
            free_list[i] = i + 1;
        }
        free_list[MAP_MAX_SIZE - 1] = END_OF_LIST;
        // header->magic = MAGIC_NUMBER; // should be atomic
        __atomic_store_n(&header->magic, MAGIC_NUMBER, __ATOMIC_SEQ_CST);
    }
    else
    {
        int *free_list = (int *)((char *)addr + sizeof(struct Header) + MAP_MAX_SIZE * sizeof(struct Entry));
        struct Entry *entries = (struct Entry *)((char *)addr + sizeof(struct Header));
        int temp_arr[MAP_MAX_SIZE] = {0};
        int curr = header->start_index;
        if (header->start_index == ALL_FILLED)
        {
            for (int i = 0; i < MAP_MAX_SIZE; ++i)
            {
                my_insert(*fast_map, entries[i].key, &entries[i].value, i);
            }
        }
        else
        {
            while (free_list[curr] != END_OF_LIST)
            {
                temp_arr[curr] = NONE_ZERO_VALUE;
                curr = free_list[curr];
            }
            temp_arr[curr] = NONE_ZERO_VALUE;
            for (int i = 0; i < MAP_MAX_SIZE; ++i)
            {
                if (temp_arr[i] == 0)
                {
                    my_insert(*fast_map, entries[i].key, &entries[i].value, i);
                }
            }
        }
    }

    return addr;
}

bool insert_db(void *addr, void *fast_map, unsigned long key, struct nfs_fh3 *value)
{
    struct Header *header = (struct Header *)addr;
    struct Entry *entries = (struct Entry *)((char *)addr + sizeof(struct Header));
    int *free_list = (int *)((char *)addr + sizeof(struct Header) + MAP_MAX_SIZE * sizeof(struct Entry));

    if (header->start_index == ALL_FILLED)
    {
        printf("error: MAP IS FILLED !\n");
        return false;
    }

    int index = header->start_index;
    entries[index].key = key;
    memcpy(&entries[index].value, value, sizeof(struct nfs_fh3));

    my_insert(fast_map, key, value, index);

    if (free_list[index] == END_OF_LIST)
    {
        // header->start_index = ALL_FILLED; // THIS SHOULD BE ATOMIC !
        __atomic_store_n(&header->start_index, ALL_FILLED, __ATOMIC_SEQ_CST);
    }
    else
    {
        // header->start_index = free_list[index]; // THIS SHOULD BE ATOMIC !
        __atomic_store_n(&header->start_index, free_list[index], __ATOMIC_SEQ_CST);
    }
    return true;
}

bool delete_entry_db(void *addr, void *fast_map, unsigned long key)
{
    struct Header *header = (struct Header *)addr;
    struct Entry *entries = (struct Entry *)((char *)addr + sizeof(struct Header));
    int *free_list = (int *)((char *)addr + sizeof(struct Header) + MAP_MAX_SIZE * sizeof(struct Entry));

    int index = -9;
    my_get_value(fast_map, key, &index);
    my_remove(fast_map, key);

    if (header->start_index == ALL_FILLED)
    {
        free_list[index] = END_OF_LIST;
    }
    else
    {
        free_list[index] = header->start_index;
    }

    // header->start_index = index; // should be atomic
    __atomic_store_n(&header->start_index, index, __ATOMIC_SEQ_CST);

    return true;
}

struct nfs_fh3 *get_db(void *fast_map, unsigned long key)
{
    int temp_index;
    return my_get_value(fast_map, key, &temp_index);
}

int main(void)
{
    return -1;
}