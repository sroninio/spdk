#ifndef MAP2_H
#define MAP2_H

#include <stdio.h>
#include <stdlib.h>

#define INITIAL_SIZE 16

typedef struct Entry
{
    unsigned long key;
    void *value;
    struct Entry *next;
} Entry;

typedef struct
{
    Entry **buckets;
    int size;
    int count;
} HashMap;

unsigned int hash(unsigned long key);
HashMap *create_map(int size);
void resize_map(HashMap *map);
void insert(HashMap *map, unsigned long key, void *value);
void *get(HashMap *map, unsigned long key);
void resize_map(HashMap *map);
void free_map(HashMap *map);
void print_map(HashMap *map);

#endif