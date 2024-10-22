#ifndef MYDB_H
#define MYDB_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <stdbool.h>
#include "volatile_map.h"
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"
#include "libnfs-raw-nfs.h"
#include <spdk/barrier.h>

#define MAGIC_NUMBER 0x12345678
#define END_OF_LIST -1
#define NONE_ZERO_VALUE 17
#define INVALID -1
#define FH_DATA_MAX_SIZE 300
#define ROOT_INODE 1
#define REGULAR_STATE 1
#define PENDING_DELETION_STATE 2

struct Header
{
    int head;
    int magic;
    unsigned long global_key;
    size_t size;
};

struct persistent_nfs_fh3
{
    struct
    {
        unsigned int data_len;
        char data_val[FH_DATA_MAX_SIZE];
    } data;
};

struct Entry
{
    unsigned long key;
    unsigned long ref_count;
    struct persistent_nfs_fh3 value;
    int next;
    int state;
};

struct PersistentDataBase
{
    struct Header header;
    struct Entry entries[];
};

typedef struct PersistentDataBase *DBptr;
typedef void *MyMapPtr;

struct DB
{
    DBptr db;
    MyMapPtr fast_map;
};
typedef struct DB DB;

/**
 * @brief Initializes or restores a persistent map database
 *
 * @param filename The name of the log file to be used for persistence
 * @param size The number of entries to allocate in the data structure
 *
 * @return DB* A pointer to the Database structure
 *
 * @details
 * If this is the first time the function is called for this file:
 * - Initializes an empty data structure
 * - Creates an empty fast map
 * - Creates an empty slow map
 *
 * If the database was previously initialized:
 * - Restores the fast map from the file
 * - Ignores the 'size' parameter and maintains the original size of the map
 */
DB *alloc_init_map_db(const char *filename, size_t size);

/**
 * @brief Inserts a new key-value pair into the database
 *
 * @param db Pointer to the database structure
 * @param key The key to insert
 * @param value Pointer to the value (nfs_fh3 structure) to insert
 *
 * @return bool True if insertion was successful, false if the map is full
 *
 * @details
 * - Checks if the map is full before insertion
 * - Inserts the key-value pair into both the persistent storage and the fast map
 * - Updates the linked list of free cells
 * - Uses a memory barrier to ensure proper ordering of memory operations
 *
 * @note Returns false and prints an error message if the map is already full
 */
bool insert_db(DB *data_base, unsigned long key, struct nfs_fh3 *value);

/**
 * @brief Deletes an entry from the database
 *
 * @param db Pointer to the database structure
 * @param key The key of the entry to delete
 *
 * @return bool True if deletion was successful, false if the key doesn't exist
 *
 * @details
 * - Removes the entry from both the fast map and the persistent storage
 * - Updates the linked list of free cells
 * - Uses a memory barrier to ensure proper ordering of memory operations
 *
 * @note Returns false and prints an error message if the key doesn't exist in the map
 */
bool delete_entry_db(DB *data_base, unsigned long key);

/**
 * @brief Retrieves a value from the database given a key
 *
 * @param fast_map The in-memory map for fast access
 * @param key The key to look up
 *
 * @return struct nfs_fh3* Pointer to the value associated with the key, or NULL if not found
 *
 * @details
 * - Searches for the key in the fast map
 * - Returns the associated value if found
 * - The index of the entry in the persistent storage is stored in a temporary variable,
 *   but not used in this function
 *
 * @note This function only accesses the fast map, not the persistent storage
 */
struct nfs_fh3 *get_db(DB *data_base, unsigned long key);

bool fh_exist_db(DB *data_base, struct nfs_fh3 *fh, unsigned long *answer);

unsigned long get_ref_count_db(DB *data_base, unsigned long key);

void increment_ref_count_db(DB *data_base, unsigned long key);

void decrement_ref_count_db(DB *data_base, unsigned long key);

void set_pending_deletion_flag(DB *data_base, unsigned long key);

bool is_valid_entry_db(DB *data_base, unsigned long key);

unsigned long generate_new_key_db(DB *data_base);

#endif // MYDB_H