#include "persistent_map.h"

static void intiallizeDB(DBptr db, size_t size)
{
    db->header.size = size;
    db->header.head = 0;
    for (int i = 0; i < (int)db->header.size; ++i)
    {
        db->entries[i].next = (i == (int)db->header.size - 1) ? (int)END_OF_LIST : i + 1;
    }

    spdk_compiler_barrier();
    db->header.magic = MAGIC_NUMBER;
}

static void restoreDB(DBptr db, MyMapPtr fast_map, int fd, size_t full_size)
{
    bool *is_free_arr = calloc(db->header.size, sizeof(bool));
    if (is_free_arr == NULL)
    {
        printf("Error: calloc failed in restoring attempt\n");
        close(fd);
        munmap(db, full_size);
        return;
    }

    int curr_index = db->header.head;
    while (curr_index != END_OF_LIST)
    {
        is_free_arr[curr_index] = true;
        curr_index = db->entries[curr_index].next;
    }

    for (size_t i = 0; i < db->header.size; ++i)
    {
        if (is_free_arr[i] == false)
        {
            volatile_map_insert(fast_map, db->entries[i].key, &db->entries[i].value, i);
        }
    }
    free(is_free_arr);
}

static void insert_entry_to_persistent_map(int free_cell, struct nfs_fh3 *value, DBptr db, MyMapPtr fast_map, unsigned long key)
{
    db->entries[free_cell].key = key;
    db->entries[free_cell].value.data.data_len = value->data.data_len;
    db->entries[free_cell].value.data.data_val = (char *)malloc(sizeof(char) * value->data.data_len);

    if (db->entries[free_cell].value.data.data_val == NULL)
    {
        printf("Error: failed to allocate memory for new FH in persistent map \n");
        return;
    }

    memcpy(db->entries[free_cell].value.data.data_val, value->data.data_val, value->data.data_len);
    volatile_map_insert(fast_map, key, value, free_cell);
}

DB *alloc_init_map_db(const char *filename, size_t size)
{
    printf("$$$$$");
    printf("\033[35m$$$$ INIT OF THE NEW DATA BASE $$$$$\033[0m"); // maybe delete later
    printf("$$$$$\n");

    int fd = open(filename, O_RDWR | O_CREAT, 0666);
    if (fd == -1)
    {
        printf("Error: in opening file");
        return NULL;
    }

    size_t full_size = sizeof(struct PersistentDataBase) + size * sizeof(struct Entry);
    if (ftruncate(fd, full_size) == -1)
    {
        printf("Error: setting file size");
        close(fd);
        return NULL;
    }

    DBptr db = mmap(NULL, full_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (db == MAP_FAILED)
    {
        printf("Error: error mapping file");
        close(fd);
        return NULL;
    }

    MyMapPtr fast_map = create_volatile_map();
    DB *data_base = malloc(sizeof(DB));
    data_base->db = db;
    data_base->fast_map = fast_map;

    if (db->header.magic != MAGIC_NUMBER)
    {
        intiallizeDB(db, size);
        spdk_compiler_barrier();
    }
    else
    {
        restoreDB(db, fast_map, fd, full_size);
    }
    return data_base;
}

bool insert_db(DB *data_base, unsigned long key, struct nfs_fh3 *value)
{
    printf("$$$$$\n");
    printf("\033[35m$$$$ INSERTING TO THE NEW DATA BASE $$$$$\033[0m"); // maybe delete later
    printf("$$$$$\n");

    int index_exists = -1;
    if (volatile_map_get_value(data_base->fast_map, key, &index_exists) != NULL)
    {
        printf("we got this value already !! key = %ld \n", key);

        if (data_base->db->entries[index_exists].value.data.data_len == value->data.data_len &&
            memcmp(data_base->db->entries[index_exists].value.data.data_val, value->data.data_val, value->data.data_len))
        {
            return true;
        }
        printf("Error: Trying to give to differents indoes same FH\n");
        return false;
    }

    int free_cell = data_base->db->header.head;

    if (free_cell == END_OF_LIST)
    {
        printf("error: MAP IS FILLED !\n");
        return false;
    }

    insert_entry_to_persistent_map(free_cell, value, data_base->db, data_base->fast_map, key);

    int new_head = (data_base->db->entries[free_cell].next == END_OF_LIST) ? END_OF_LIST : data_base->db->entries[free_cell].next;

    spdk_compiler_barrier();
    data_base->db->header.head = new_head;
    spdk_compiler_barrier();

    return true;
}

bool delete_entry_db(DB *data_base, unsigned long key)
{
    int index = INVALID;
    volatile_map_get_value(data_base->fast_map, key, &index);

    if (index == INVALID || volatile_map_remove(data_base->fast_map, key) == false)
    {
        printf("Error: error in removing a none existing entry\n");
        return false;
    }

    data_base->db->entries[index].next = (data_base->db->header.head == END_OF_LIST) ? END_OF_LIST : data_base->db->header.head;

    spdk_compiler_barrier();
    data_base->db->header.head = index;
    spdk_compiler_barrier();

    return true;
}

struct nfs_fh3 *get_db(DB *data_base, unsigned long key)
{
    int temp_index;
    return volatile_map_get_value(data_base->fast_map, key, &temp_index);
}

bool fh_exist_db(DB *data_base, struct nfs_fh3 *fh, unsigned long *answer)
{
    return volatile_map_is_fh_exist(data_base->fast_map, fh, answer);
}