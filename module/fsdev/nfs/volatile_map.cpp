#include "volatile_map.h"
#include <iostream>
#include <unordered_map>
#include <cstring>
#include <cassert>

extern "C"
{
    void *create_volatile_map(void)
    {
        // return new std::unordered_map<unsigned long, struct nfs_fh3>;
        return new std::unordered_map<unsigned long, std::pair<struct nfs_fh3, int>>;
    }

    // returning the value, and putting the map[key].index in the index pointer we got
    struct nfs_fh3 *volatile_map_get_value(void *map, unsigned long key, int *index)
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
        *index = -1; // or some other sentinel value
        if (my_map->size() != initial_size)
        { // Verify size hasn't changed
            printf("ERROR: inserting grabge value into MAP !!!\n");
        }
        return nullptr;
    }

    void volatile_map_insert(void *map, unsigned long key, struct nfs_fh3 *fh, int index)
    {
        struct nfs_fh3 tmp = {};
        std::unordered_map<unsigned long, std::pair<struct nfs_fh3, int>> *my_map = (std::unordered_map<unsigned long, std::pair<struct nfs_fh3, int>> *)map;

        tmp.data.data_len = fh->data.data_len;
        tmp.data.data_val = (char *)malloc(tmp.data.data_len);
        memcpy(tmp.data.data_val, fh->data.data_val, tmp.data.data_len);
        (*my_map)[key] = std::make_pair(tmp, index);
    }

    bool volatile_map_remove(void *map, unsigned long key)
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

    bool volatile_map_is_fh_exist(void *map, struct nfs_fh3 *fh, unsigned long *answer)
    {
        std::unordered_map<unsigned long, std::pair<struct nfs_fh3, int>> *my_map =
            (std::unordered_map<unsigned long, std::pair<struct nfs_fh3, int>> *)map;

        for (const auto &pair : *my_map)
        {
            const struct nfs_fh3 &current_fh = pair.second.first;

            // Compare the nfs_fh3 structures
            if (current_fh.data.data_len == fh->data.data_len &&
                memcmp(current_fh.data.data_val, fh->data.data_val, current_fh.data.data_len) == 0)
            {

                *answer = pair.first; // Set the answer to the key
                return true;
            }
        }

        *answer = 2; // Set to 2 if not found
        return false;
    }
}
