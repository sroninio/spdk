#include "mymap.h"
#include <iostream>
#include <unordered_map>
#include <cstring>

extern "C"
{
    void *create_my_map(void)
    {
        return new std::unordered_map<unsigned long, struct nfs_fh3>;
    }

    struct nfs_fh3 *my_get(void *map, unsigned long key)
    {
        printf("entered get !!! \n");
        std::unordered_map<unsigned long, struct nfs_fh3> *my_map = (std::unordered_map<unsigned long, struct nfs_fh3> *)map;
        return &((*my_map)[key]);
    }

    void my_insert(void *map, unsigned long key, struct nfs_fh3 *fh)
    {
        struct nfs_fh3 tmp = {};
        std::unordered_map<unsigned long, struct nfs_fh3> *my_map = (std::unordered_map<unsigned long, struct nfs_fh3> *)map;

        tmp.data.data_len = fh->data.data_len;
        tmp.data.data_val = (char *)malloc(tmp.data.data_len);
        memcpy(tmp.data.data_val, fh->data.data_val, tmp.data.data_len);
        (*my_map)[key] = tmp;
    }
}
