#include "map2.h"

unsigned int hash(unsigned long key) {
    return key % INITIAL_SIZE;
}

HashMap *create_map(int size) {
    HashMap *map = (HashMap *)malloc(sizeof(HashMap));
    map->size = size;
    map->count = 0;
    map->buckets = (Entry **)calloc(map->size, sizeof(Entry *));
    return map;
}

void resize_map(HashMap *map);

void insert(HashMap *map, unsigned long key, void *value) {
    unsigned int index = hash(key) % map->size;
    Entry *entry = map->buckets[index];

    while (entry != NULL) {
        if (entry->key == key) {
            entry->value = value;
            return;
        }
        entry = entry->next;
    }

    Entry *new_entry = (Entry *)malloc(sizeof(Entry));
    new_entry->key = key;
    new_entry->value = value;
    new_entry->next = map->buckets[index];
    map->buckets[index] = new_entry;
    map->count++;

    if ((float)map->count / map->size > 0.75) {
        resize_map(map);
    }
}

void *get(HashMap *map, unsigned long key) {
    unsigned int index = hash(key) % map->size;
    Entry *entry = map->buckets[index];

    while (entry != NULL) {
        if (entry->key == key) {
            return entry->value;
        }
        entry = entry->next;
    }

    // Key not found, insert with default value NULL
    insert(map, key, NULL);
    return NULL;
}

void resize_map(HashMap *map) {
    int new_size = map->size * 2;
    Entry **new_buckets = (Entry **)calloc(new_size, sizeof(Entry *));

    for (int i = 0; i < map->size; i++) {
        Entry *entry = map->buckets[i];
        while (entry != NULL) {
            Entry *next = entry->next;
            unsigned int index = hash(entry->key) % new_size;
            entry->next = new_buckets[index];
            new_buckets[index] = entry;
            entry = next;
        }
    }

    free(map->buckets);
    map->buckets = new_buckets;
    map->size = new_size;
}

void free_map(HashMap *map) {
    for (int i = 0; i < map->size; i++) {
        Entry *entry = map->buckets[i];
        while (entry != NULL) {
            Entry *next = entry->next;
            free(entry);
            entry = next;
        }
    }
    free(map->buckets);
    free(map);
}

void print_map(HashMap *map) {
    for (int i = 0; i < map->size; i++) {
        Entry *entry = map->buckets[i];
        while (entry != NULL) {
            printf("%lu: %p\n", entry->key, entry->value);
            entry = entry->next;
        }
    }
}

// int main() {
//     HashMap *map = create_map(INITIAL_SIZE);

//     int value1 = 42;
//     insert(map, 123456789UL, &value1);
//     int value2 = 84;
//     insert(map, 987654321UL, &value2);

//     printf("Initial map:\n");
//     print_map(map);

//     printf("\nGet non-existing key 555555555: %p\n", get(map, 555555555UL));

//     printf("\nMap after accessing non-existing key:\n");
//     print_map(map);

//     void* ptr =  get(map, 123456789UL);
//     printf("we got the value of %p \n", ptr);
//     printf("we got the value of ^^%p^^ \n", get(map, 11UL));
//     printf("\nafter\n");
//     print_map(map);


//     printf("\nwe got the value of ^^%p^^ \n", get(map, 123456789UL));

//     int value3 = 5;
//     printf("\n value3 pointer value of ^^%p^^ \n", &value3);
//     insert(map, 123456789UL, &value3);
//     printf("we got the value of ^^%p^^ \n", get(map, 123456789UL));



//     printf("\nwe here \n");

//     free_map(map);
//     return 0;
// }