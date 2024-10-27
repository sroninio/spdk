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
#define INVALID -1
#define ROOT_INODE 1

#define FH_DATA_MAX_SIZE 300
#define MAX_FILE_NAME 255

enum EntryState
{
    REGULAR_STATE = 1,
    PENDING_DELETION_STATE = 2
};

struct Header
{
    int magic;
    int free_list_head;
    unsigned long global_key;
    size_t persistent_db_max_size;
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
    enum EntryState state;
    struct
    {
        struct persistent_nfs_fh3 parent_fh;
        char name[MAX_FILE_NAME];
    } delete_params;
};

struct PersistentDataBase
{
    struct Header header;
    struct Entry entries[];
};

typedef void *MyMapPtr;

struct DB
{
    struct PersistentDataBase *db;
    MyMapPtr fast_map;
};

/**
 * Initializes or restores a persistent map database from a file.
 *
 * @param filename The name of the file to store the persistent database.
 * @param size The number of entries to allocate in the database.
 * @return A pointer to the initialized DB structure, or NULL on failure.
 *
 * If the file doesn't exist or is empty, it initializes a new database.
 * If the file contains existing data, it restores the database from the file.
 */
struct DB *alloc_init_map_db(const char *filename, size_t size);

/**
 * Inserts a new key-value pair into the database.
 *
 * @param data_base Pointer to the DB structure.
 * @param key The key to insert (unsigned long).
 * @param value Pointer to the nfs_fh3 structure to be inserted.
 * @return true if insertion was successful, false if the key already exists or the database is full.
 *
 * Updates both the persistent storage and the in-memory fast map.
 */
bool insert_entry_db(struct DB *data_base, unsigned long key, struct nfs_fh3 *value);

/**
 * Deletes an entry from the database given its key.
 *
 * @param data_base Pointer to the DB structure.
 * @param key The key of the entry to delete.
 * @return true if deletion was successful, false if the key doesn't exist.
 *
 * Removes the entry from both the persistent storage and the in-memory fast map.
 */
bool delete_entry_db(struct DB *data_base, unsigned long key);

/**
 * Retrieves a file handle from the database given a key.
 *
 * @param data_base Pointer to the DB structure.
 * @param key The key to look up.
 * @return Pointer to the nfs_fh3 structure if found, NULL if not found.
 *
 * This function only accesses the in-memory fast map for quick retrieval.
 */
struct nfs_fh3 *get_fh_db(struct DB *data_base, unsigned long key);

/**
 * Gets the reference count for a given key in the database.
 *
 * @param data_base Pointer to the DB structure.
 * @param key The key to look up.
 * @return The reference count as an unsigned long, or 0 if the key doesn't exist.
 */
unsigned long get_ref_count_db(struct DB *data_base, unsigned long key);

/**
 * Retrieves the parent file handle's data value for a given key.
 *
 * @param data_base Pointer to the DB structure.
 * @param key The key to look up.
 * @return Pointer to the parent file handle's data value, or NULL if the key doesn't exist.
 */
char *get_entry_parent_data_val_db(struct DB *data_base, unsigned long key);

/**
 * Gets the length of the parent file handle's data for a given key.
 *
 * @param data_base Pointer to the DB structure.
 * @param key The key to look up.
 * @return The length of the parent file handle's data, or -1 if the key doesn't exist.
 */
int get_entry_parent_data_len_db(struct DB *data_base, unsigned long key);

/**
 * Retrieves the name associated with a given key in the database.
 *
 * @param data_base Pointer to the DB structure.
 * @param key The key to look up.
 * @return Pointer to the name string, or NULL if the key doesn't exist.
 */
char *get_entry_name_db(struct DB *data_base, unsigned long key);

/**
 * Gets the state of an entry (regular or pending deletion) for a given key.
 *
 * @param data_base Pointer to the DB structure.
 * @param key The key to look up.
 * @return The EntryState enum value (REGULAR_STATE or PENDING_DELETION_STATE).
 */
enum EntryState get_entry_state_db(struct DB *data_base, unsigned long key);

/**
 * Checks if a file handle exists in the database and returns its key if found.
 *
 * @param data_base Pointer to the DB structure.
 * @param fh Pointer to the nfs_fh3 structure to look up.
 * @param answer Pointer to store the key if found.
 * @return true if the file handle exists, false otherwise.
 */
bool fh_exist_db(struct DB *data_base, struct nfs_fh3 *fh, unsigned long *answer);

/**
 * Increments the reference count for a given key in the database.
 *
 * @param data_base Pointer to the DB structure.
 * @param key The key whose reference count should be incremented.
 */
void increment_ref_count_db(struct DB *data_base, unsigned long key);

/**
 * Decrements the reference count for a given key in the database.
 *
 * @param data_base Pointer to the DB structure.
 * @param key The key whose reference count should be decremented.
 */
void decrement_ref_count_db(struct DB *data_base, unsigned long key);

/**
 * Sets the pending deletion flag for a given key in the database.
 *
 * @param data_base Pointer to the DB structure.
 * @param key The key whose state should be set to pending deletion.
 */
void set_pending_deletion_flag_db(struct DB *data_base, unsigned long key);

/**
 * Sets the parent file handle and name for a given key in the database.
 *
 * @param data_base Pointer to the DB structure.
 * @param key The key for which to set the parent and name.
 * @param name The name to set (must be shorter than MAX_FILE_NAME).
 * @param parent_fh Pointer to the parent's nfs_fh3 structure.
 * @return true if successful, false if the key doesn't exist or the name is too long.
 */
bool set_parent_fh_and_name_db(struct DB *data_base, unsigned long key, const char *name, struct nfs_fh3 *parent_fh);

/**
 * Generates a new unique key for the database.
 *
 * @param data_base Pointer to the DB structure.
 * @return A new unique key (unsigned long).
 *
 * Increments and returns the global_key value from the database header.
 */
unsigned long generate_new_key_db(struct DB *data_base);

#endif // MYDB_H