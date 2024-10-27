#include "volatile_map.h"
#include <iostream>
#include <unordered_map>
#include <cstring>
#include <cassert>
#include <boost/bimap.hpp>
#include <boost/bimap/unordered_set_of.hpp>
#include <boost/functional/hash.hpp>
#include <iostream>
#include <string>

struct MapData
{
    struct nfs_fh3 fh;
    int index;

    MapData(const struct nfs_fh3 *filehandle, int i) : index(i)
    {
        fh.data.data_len = filehandle->data.data_len;
        fh.data.data_val = (char *)malloc(filehandle->data.data_len * sizeof(char));
        if (fh.data.data_val == NULL)
        {
            printf("Error: not able to allocated new memory for entries of map\n");
            return;
        }
        memcpy(fh.data.data_val, filehandle->data.data_val, fh.data.data_len);
    }

    bool operator==(const MapData &other) const
    {
        return (fh.data.data_len == other.fh.data.data_len) &&
               ((std::memcmp(fh.data.data_val, other.fh.data.data_val, fh.data.data_len)) == 0);
    }
};

struct MapDataHash
{
    std::size_t operator()(const MapData &data) const
    {
        return boost::hash_range(data.fh.data.data_val, data.fh.data.data_val + data.fh.data.data_len);
    }
};

typedef boost::bimap<
    boost::bimaps::unordered_set_of<unsigned long>,
    boost::bimaps::unordered_set_of<MapData, MapDataHash>>
    VolatileBimap;

extern "C"
{

    void *
    create_volatile_map(void)
    {
        return new VolatileBimap;
    }

    // returning the value, and putting the map[key].index in the index pointer we got
    struct nfs_fh3 *volatile_map_get_fh_and_persistent_map_index(void *map, unsigned long key, int *index)
    {
        VolatileBimap *my_map = static_cast<VolatileBimap *>(map);
        auto it = my_map->left.find(key);
        if (it != my_map->left.end())
        {
            *index = it->second->index;

            return const_cast<struct nfs_fh3 *>(&(it->second->fh));
        }

        *index = -1;
        return nullptr;
    }

    void volatile_map_insert_entry_with_persistent_map_index(void *map, unsigned long key, struct nfs_fh3 *fh, int index)
    {
        VolatileBimap *my_map = static_cast<VolatileBimap *>(map);

        MapData mapData(fh, index);

        auto result = my_map->insert(VolatileBimap::value_type(key, mapData));

        if (!result.second)
        {
            printf("Warning: Key %lu already exists in the map. Value not inserted.\n", key);
            free(mapData.fh.data.data_val);
        }
    }

    bool volatile_map_remove(void *map, unsigned long key)
    {
        VolatileBimap *my_map = static_cast<VolatileBimap *>(map);

        auto it = my_map->left.find(key);
        if (it != my_map->left.end())
        {
            my_map->left.erase(it);
            free(it->fh.data.data_val);
            return true;
        }
        return false;
    }

    bool volatile_map_is_fh_exist(void *map, struct nfs_fh3 *fh, unsigned long *answer)
    {
        VolatileBimap *my_map = static_cast<VolatileBimap *>(map);

        // Create a temporary MapData object for comparison
        MapData search_data(fh, 0); // The index doesn't matter for searching

        auto it = my_map->right.find(search_data);
        if (it != my_map->right.end())
        {
            *answer = it->second; // Set the answer to the key (unsigned long)
            return true;
        }

        *answer = 0;
        return false;
    }
}
