#include "persistent_map.h"

void print_list(DBptr db) //
{
    printf("=================================== PRINTING STATUS :\n");
    for (int i = 0; i < db->header.size + 1; ++i) //
    {
        if (i == 0)
        {
            printf("key  : ");
        }
        else
        {
            printf("| %ld ", db->entries[i - 1].key); //
        }
    } //
    printf("|\n");
    for (int i = 0; i < db->header.size + 1; ++i) //
    {
        if (i == 0)
        {
            printf("next : ");
        }
        else
        {
            printf("| %d ", db->entries[i - 1].next); //
        }
    } //
    printf("|\n");
    printf("DB->HEADER->HEAD = %d \n", db->header.head);
    printf("=================================== END :\n");
}

DBptr init_map_db(const char *filename, MyMap *fast_map, int size)
{
    if (size <= 0)
    {
        printf("Error: negative size in not valid parameter \n");
        return NULL;
    }

    int fd = open(filename, O_RDWR | O_CREAT, 0666);
    if (fd == -1)
    {
        perror("Error: in opening file");
        return NULL;
    }

    size_t full_size = sizeof(struct DataBase) + (size_t)size * sizeof(struct Entry);
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

    *fast_map = create_my_map();
    if (db->header.magic != MAGIC_NUMBER)
    {
        // printf("should init != MAGIC ============= \n"); //
        db->header.size = size;
        db->header.head = 0;
        for (int i = 0; i < db->header.size - 1; ++i)
        {
            db->entries[i].next = i + 1;
        }
        db->entries[db->header.size - 1].next = END_OF_LIST;

        __sync_synchronize();

        db->header.magic = MAGIC_NUMBER;
        // print_list(db); //
    }
    else
    {
        // printf("should restore == MAGIC ============= \n");          //
        // printf("the header->size field is %ld \n", db->header.size); //
        // print_list(db);                                              //

        if (db->header.head == ALL_FILLED)
        {
            for (int i = 0; i < db->header.size; ++i)
            {
                my_insert(*fast_map, db->entries[i].key, &db->entries[i].value, i);
            }
        }
        else
        {
            int *temp_arr = calloc(db->header.size, sizeof(int));
            if (temp_arr == NULL)
            {
                printf("Error: calloc failed in restoring attempt\n");
                close(fd);
                munmap(db, full_size);
                return NULL;
            }

            int curr_index = db->header.head;
            while (db->entries[curr_index].next != END_OF_LIST)
            {
                // printf("yupp \n"); //
                temp_arr[curr_index] = NONE_ZERO_VALUE;
                curr_index = db->entries[curr_index].next;
            }
            temp_arr[curr_index] = NONE_ZERO_VALUE;
            for (int i = 0; i < db->header.size; ++i)
            {
                if (temp_arr[i] == 0)
                {
                    my_insert(*fast_map, db->entries[i].key, &db->entries[i].value, i);
                }
            }
            free(temp_arr);
        }
    }
    return db;
}

bool insert_db(DBptr db, MyMap fast_map, unsigned long key, struct nfs_fh3 *value)
{
    // printf("INSERT_DB [key = %ld]\n", key); //
    // printf("BEFORE : \n");                  //
    // print_list(db);                         //
    if (db->header.head == ALL_FILLED)
    {
        printf("error: MAP IS FILLED !\n");
        return false;
    }

    int free_cell = db->header.head;
    db->entries[free_cell].key = key;
    memcpy(&db->entries[free_cell].value, value, sizeof(struct nfs_fh3));
    my_insert(fast_map, key, value, free_cell);

    int new_head;
    if (db->entries[free_cell].next == END_OF_LIST)
    {
        new_head = ALL_FILLED;
    }
    else
    {
        new_head = db->entries[free_cell].next;
    }

    __sync_synchronize();

    db->header.head = new_head;
    // printf("AFTER : \n"); //
    // print_list(db);       //

    return true;
}

bool delete_entry_db(DBptr db, MyMap fast_map, unsigned long key)
{
    // printf("DELETE_DB [key = %ld]\n", key); //
    // printf("BEFORE : \n");                  //
    // print_list(db);                         //
    int index = -9;
    my_get_value(fast_map, key, &index);
    my_remove(fast_map, key);

    if (index == -9)
    {
        printf("Error: error in removing a none existing entry\n");
        return false;
    }

    if (db->header.head == ALL_FILLED)
    {
        db->entries[index].next = END_OF_LIST;
    }
    else
    {
        db->entries[index].next = db->header.head;
    }

    __sync_synchronize();

    db->header.head = index;
    // printf("AFTER : \n"); //
    // print_list(db);       //
    return true;
}

struct nfs_fh3 *get_db(MyMap fast_map, unsigned long key)
{
    int temp_index;
    return my_get_value(fast_map, key, &temp_index);
}

// int main(void)
// {
//     printf("my name is slim shady \n");
//     return -1;
// }
