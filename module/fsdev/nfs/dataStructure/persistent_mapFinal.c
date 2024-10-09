#include "persistent_map.h"

void print_list(DB *data_base)
{
    printf("=================================== PRINTING STATUS :\n");
    for (int i = 0; i < data_base->db->header.size + 1; ++i) //
    {
        if (i == 0)
        {
            printf("key  : ");
        }
        else
        {
            printf("| %ld ", data_base->db->entries[i - 1].key); //
        }
    } //
    printf("|\n");
    for (int i = 0; i < data_base->db->header.size + 1; ++i) //
    {
        if (i == 0)
        {
            printf("next : ");
        }
        else
        {
            printf("| %d ", data_base->db->entries[i - 1].next); //
        }
    } //
    printf("|\n");
    printf("DB->HEADER->HEAD = %d \n", data_base->db->header.head);
    printf("=================================== END :\n");
}

static void intiallizeDB(DBptr db, size_t size)
{
    db->header.size = size;
    db->header.head = 0;
    for (size_t i = 0; i < db->header.size; ++i)
    {
        db->entries[i].next = (i == db->header.size - 1) ? END_OF_LIST : i + 1;
    }

    __sync_synchronize();
    db->header.magic = MAGIC_NUMBER;
}

static void restoreDB(DBptr db, MyMapPtr fast_map, int fd, size_t full_size)
{
    bool *is_free_arr = calloc(db->header.size, sizeof(int));
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

    for (int i = 0; i < db->header.size; ++i)
    {
        if (is_free_arr[i] == false)
        {
            my_insert(fast_map, db->entries[i].key, &db->entries[i].value, i);
        }
    }
    free(is_free_arr);
}

static void insert_entry_to_persistent_map(int free_cell, struct nfs_fh3 *value, DBptr db, MyMapPtr fast_map, unsigned long key)
{
    memcpy(&db->entries[free_cell].value, value, sizeof(struct nfs_fh3));
    my_insert(fast_map, key, value, free_cell);
}

DB *init_map_db(const char *filename, size_t size)
{
    int fd = open(filename, O_RDWR | O_CREAT, 0666);
    if (fd == -1)
    {
        perror("Error: in opening file");
        return NULL;
    }

    size_t full_size = sizeof(struct PersistentDataBase) + size * sizeof(struct Entry);
    if (ftruncate(fd, full_size) == -1)
    {
        perror("Error: setting file size");
        close(fd);
        return NULL;
    }

    DBptr db = mmap(NULL, full_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (db == MAP_FAILED)
    {
        perror("Error: error mapping file");
        close(fd);
        return NULL;
    }

    MyMapPtr fast_map = create_my_map();
    DB *data_base = malloc(sizeof(DB));
    data_base->db = db;
    data_base->fast_map = fast_map;

    if (db->header.magic != MAGIC_NUMBER)
    {
        intiallizeDB(db, size);
        __sync_synchronize();
    }
    else
    {
        restoreDB(db, fast_map, fd, full_size);
    }

    return data_base;
}

bool insert_db(DB *data_base, unsigned long key, struct nfs_fh3 *value)
{
    int index_exists = -1;

    if (my_get_value(data_base->fast_map, key, &index_exists) != NULL && index_exists != -1)
    {
        memcpy(&data_base->db->entries[index_exists].value, value, sizeof(struct nfs_fh3));
        my_insert(data_base->fast_map, key, value, index_exists);
        return true;
    }

    if (data_base->db->header.head == ALL_FILLED)
    {
        printf("error: MAP IS FILLED !\n");
        return false;
    }

    int free_cell = data_base->db->header.head;
    data_base->db->entries[free_cell].key = key;
    insert_entry_to_persistent_map(free_cell, value, data_base->db, data_base->fast_map, key);

    int new_head;
    if (data_base->db->entries[free_cell].next == END_OF_LIST)
    {
        new_head = ALL_FILLED;
    }
    else
    {
        new_head = data_base->db->entries[free_cell].next;
    }

    __sync_synchronize();
    data_base->db->header.head = new_head;
    __sync_synchronize();

    return true;
}

bool delete_entry_db(DB *data_base, unsigned long key)
{
    int index = INVALID;
    my_get_value(data_base->fast_map, key, &index);

    if (index == INVALID || my_remove(data_base->fast_map, key) == false)
    {
        printf("Error: error in removing a none existing entry\n");
        return false;
    }

    if (data_base->db->header.head == ALL_FILLED)
    {
        data_base->db->entries[index].next = END_OF_LIST;
    }
    else
    {
        data_base->db->entries[index].next = data_base->db->header.head;
    }

    __sync_synchronize();
    data_base->db->header.head = index;
    __sync_synchronize();

    return true;
}

struct nfs_fh3 *get_db(DB *data_base, unsigned long key)
{
    int temp_index;
    return my_get_value(data_base->fast_map, key, &temp_index);
}

int main(void)
{
    printf("my name is slim shady \n");
    return -1;
}