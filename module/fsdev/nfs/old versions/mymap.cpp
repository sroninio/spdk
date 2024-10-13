#include "mymap.h"
#include <iostream>
#include <unordered_map>
#include <cstring>
#include <cassert>

extern "C"
{
    void *create_my_map(void)
    {
        // return new std::unordered_map<unsigned long, struct nfs_fh3>;
        return new std::unordered_map<unsigned long, std::pair<struct nfs_fh3, int>>;
    }

    // returning the value, and putting the map[key].index in the index pointer we got
    struct nfs_fh3 *my_get_value(void *map, unsigned long key, int *index)
    {
        std::unordered_map<unsigned long, std::pair<struct nfs_fh3, int>> *my_map = (std::unordered_map<unsigned long, std::pair<struct nfs_fh3, int>> *)map;
        size_t initial_size = my_map->size(); // Get initial size

        auto it = my_map->find(key);
        if (it != my_map->end())
        {
            *index = it->second.second;
            return &(it->second.first);
        }

        // Key not found
        *index = -1;                            // or some other sentinel value
        assert(my_map->size() == initial_size); // Verify size hasn't changed
        return nullptr;
    }

    void my_insert(void *map, unsigned long key, struct nfs_fh3 *fh, int index)
    {
        struct nfs_fh3 tmp = {};
        std::unordered_map<unsigned long, std::pair<struct nfs_fh3, int>> *my_map = (std::unordered_map<unsigned long, std::pair<struct nfs_fh3, int>> *)map;

        tmp.data.data_len = fh->data.data_len;
        tmp.data.data_val = (char *)malloc(tmp.data.data_len);
        // should change this later !!!!@@@@!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        tmp.data.num1 = fh->data.num1; // remember to delte !
        tmp.data.num2 = fh->data.num2; // remember to delte !
        memcpy(tmp.data.data_val, fh->data.data_val, tmp.data.data_len);
        (*my_map)[key] = std::make_pair(tmp, index);
    }

    bool my_remove(void *map, unsigned long key)
    {
        std::unordered_map<unsigned long, std::pair<struct nfs_fh3, int>> *my_map = (std::unordered_map<unsigned long, std::pair<struct nfs_fh3, int>> *)map;

        auto it = my_map->find(key);
        if (it != my_map->end())
        {
            // Free the dynamically allocated memory for nfs_fh3
            free(it->second.first.data.data_val);

            // Remove the element from the map
            my_map->erase(it);
            return true;
        }

        // Key not found
        return false;
    }
}
