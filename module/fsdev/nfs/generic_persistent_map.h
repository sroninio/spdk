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
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"
#include "libnfs-raw-nfs.h"

#include <unordered_map>
#include <iostream>
#include <string>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <algorithm>
#include <new>

#define MAGIC_NUMBER 0x12345678
#define END_OF_LIST -1
#define MAX_SIZE_DB 20
#define INVALID -1
#define NA -2

#define MAX_RIGHT_LENGHT 300 // should remove this after we ommit the std::string

class VolatileMap
{
private:
    std::unordered_map<unsigned long, std::pair<std::string, int>> m_left_key_map;
    std::unordered_map<std::string, std::pair<unsigned long, int>> m_right_key_map;

    bool Remove(unsigned long left, const std::string &right)
    {
        if (FindIndexViaLeftKey(left) == INVALID || FindIndexViaRightKey(right) == INVALID)
        {
            return false;
        }

        auto it1 = m_left_key_map.find(left);
        m_left_key_map.erase(it1);

        auto it2 = m_right_key_map.find(right);
        m_right_key_map.erase(it2);
        return true;
    }

public:
    VolatileMap(void) : m_left_key_map(), m_right_key_map() {}

    VolatileMap(const VolatileMap &other) = delete;
    VolatileMap &operator=(const VolatileMap &other) = delete;
    ~VolatileMap() = default;

    bool Insert(unsigned long left, const std::string &right, unsigned long persistent_db_index)
    {
        if (FindIndexViaLeftKey(left) != INVALID || FindIndexViaRightKey(right) != INVALID)
        {
            return false;
        }
        m_left_key_map[left] = std::make_pair(right, persistent_db_index);
        m_right_key_map[right] = std::make_pair(left, persistent_db_index);
        return true;
    }

    bool RemoveByLeftKey(unsigned long left)
    {

        if (FindIndexViaLeftKey(left) == INVALID)
        {
            return false;
        }

        std::string right = m_left_key_map[left].first;

        return Remove(left, right);
    }

    bool RemoveByRightKey(const std::string &right)
    {

        if (FindIndexViaRightKey(right) == INVALID)
        {
            return false;
        }

        unsigned long left = m_right_key_map[right].first;

        return Remove(left, right);
    }

    unsigned long FindIndexViaLeftKey(unsigned long left) const
    {

        auto it = m_left_key_map.find(left);
        if (it != m_left_key_map.end())
        {
            return it->second.second;
        }

        return INVALID;
    }

    unsigned long FindIndexViaRightKey(std::string right) const
    {
        auto it = m_right_key_map.find(right);
        if (it != m_right_key_map.end())
        {
            return it->second.second;
        }

        return INVALID;
    }
};

template <typename T>
class Entry
{
private:
    int m_next;
    unsigned long m_left;
    // std::string m_right;
    char m_right_data[MAX_RIGHT_LENGHT];
    int m_right_len;
    T m_data[2];
    int m_version;

public:
    Entry(int next, unsigned long left, std::string right, const T &value) : m_next(next), m_left(left), m_version(0)
    {
        m_right_len = right.length();
        memcpy(m_right_data, right.data(), m_right_len);

        m_data[0] = value;
        m_data[1] = value;
    }

    ~Entry() = default;

    void Update(const T &new_version)
    {
        memcpy(&(m_data[(m_version + 1) % 2]), &new_version, sizeof(T));
        spdk_compiler_barrier();
        m_version = (m_version + 1) % 2;
    }

    T *GetData(void)
    {
        return &m_data[m_version];
    }

    void SetNext(int next)
    {
        m_next = next;
    }

    int GetNext(void)
    {
        return m_next;
    }

    unsigned long GetLeftKey()
    {
        return m_left;
    }
    std::string GetRightKey()
    {
        std::string right(m_right_data, m_right_len);
        return right;
    }
};

template <typename T>
class RawPersistentDataBase
{
public:
    int m_magic;
    int m_free_list_head;
    unsigned long m_left_key_counter;
    Entry<T> m_entries[MAX_SIZE_DB];
};

template <typename T>
class PersistentMap
{
private:
    RawPersistentDataBase<T> *m_raw_persistent_data_base;
    VolatileMap m_volatile_map;

    void Init()
    {
        m_raw_persistent_data_base->m_left_key_counter = 1;
        m_raw_persistent_data_base->m_free_list_head = 0;
        for (int i = 0; i < MAX_SIZE_DB; ++i)
        {
            m_raw_persistent_data_base->m_entries[i].SetNext((i == (int)MAX_SIZE_DB - 1) ? (int)END_OF_LIST : i + 1);
        }
        spdk_compiler_barrier();
        m_raw_persistent_data_base->m_magic = MAGIC_NUMBER;
    }

    void Restore()
    {
        std::vector<bool> is_free_arr(MAX_SIZE_DB, false);

        int curr_index = m_raw_persistent_data_base->m_free_list_head;
        while (curr_index != END_OF_LIST)
        {
            is_free_arr[curr_index] = true;
            curr_index = m_raw_persistent_data_base->m_entries[curr_index].GetNext();
        }

        // for (size_t i = 0; i < MAX_SIZE_DB; ++i)
        // {
        //     std::cout << "--- " << i << " =[" << (is_free_arr[i] ? "FREE" : "NOT_FREEE") << "]" << std::endl;
        // }

        for (size_t i = 0; i < MAX_SIZE_DB; ++i)
        {
            if (!is_free_arr[i])
            {
                unsigned long left = m_raw_persistent_data_base->m_entries[i].GetLeftKey();
                std::string right = m_raw_persistent_data_base->m_entries[i].GetRightKey();
                // std::cout << "====== Entry[" << i << "] left=[" << left << "] right=[" << right << "]" << std::endl;

                bool res = m_volatile_map.Insert(left, right, i);
                if (!res)
                {
                    std::cout << "Error in restoring Entry " << i << "left=[" << left << "] right=[" << right << "]" << std::endl;
                    exit(-1);
                }
            }
        }
    }

public:
    PersistentMap(void *shmem_db) : m_volatile_map()
    {
        m_raw_persistent_data_base = static_cast<RawPersistentDataBase<T> *>(shmem_db);
        if (m_raw_persistent_data_base->m_magic != MAGIC_NUMBER)
        {
            Init();
            spdk_compiler_barrier();
        }
        else
        {
            Restore();
        }
        // m_volatile_map.print_size();
    }

    PersistentMap(const PersistentMap &other) = delete;
    PersistentMap &operator=(const PersistentMap &other) = delete;
    ~PersistentMap() = default;

    // will return false if and only if there is already entry like this
    bool InsertEntry(const T &entry, unsigned long left, const std::string &right)
    {
        int index1 = m_volatile_map.FindIndexViaLeftKey(left);
        int index2 = m_volatile_map.FindIndexViaRightKey(right);

        assert(index1 == index2);

        if (index1 != INVALID || index2 != INVALID)
        {
            std::cout << "Error: Entry Already in volatile map" << std::endl;
            return false;
        }

        int free_cell = m_raw_persistent_data_base->m_free_list_head;

        assert(free_cell != END_OF_LIST);

        int new_head = m_raw_persistent_data_base->m_entries[free_cell].GetNext();

        m_volatile_map.Insert(left, right, free_cell);

        new (&m_raw_persistent_data_base->m_entries[free_cell]) Entry<T>(NA, left, right, entry);

        spdk_compiler_barrier();
        m_raw_persistent_data_base->m_free_list_head = new_head;
        spdk_compiler_barrier();

        return true;
    }

    bool UpdateEntryByLeft(const T &entry, unsigned long left)
    {
        int index = m_volatile_map.FindIndexViaLeftKey(left);
        if (index == INVALID)
        {
            return false;
        }

        m_raw_persistent_data_base->m_entries[index].Update(entry);
        spdk_compiler_barrier();

        return true;
    }

    bool UpdateEntryByRight(const T &entry, const std::string &right)
    {
        int index = m_volatile_map.FindIndexViaRightKey(right);
        if (index == INVALID)
        {
            return false;
        }
        m_raw_persistent_data_base->m_entries[index].Update(entry);
        spdk_compiler_barrier();

        return true;
    }

    bool RemoveEntryByLeft(unsigned long left)
    {
        int index = m_volatile_map.FindIndexViaLeftKey(left);
        if (index == INVALID)
        {
            return false;
        }

        if (m_volatile_map.RemoveByLeftKey(left) == false)
        {
            return false;
        }

        m_raw_persistent_data_base->m_entries[index].SetNext(m_raw_persistent_data_base->m_free_list_head);

        spdk_compiler_barrier();
        m_raw_persistent_data_base->m_free_list_head = index;
        spdk_compiler_barrier();

        return true;
    }

    bool RemoveEntryByRight(const std::string &right)
    {
        int index = m_volatile_map.FindIndexViaRightKey(right);
        if (index == INVALID)
        {
            return false;
        }

        if (m_volatile_map.RemoveByRightKey(right) == false)
        {
            return false;
        }

        m_raw_persistent_data_base->m_entries[index].SetNext(m_raw_persistent_data_base->m_free_list_head);

        spdk_compiler_barrier();
        m_raw_persistent_data_base->m_free_list_head = index;
        spdk_compiler_barrier();

        return true;
    }

    T *GetEntryByLeft(unsigned long left) const
    {
        int index = m_volatile_map.FindIndexViaLeftKey(left);
        if (index == INVALID)
        {
            return NULL;
        }
        return m_raw_persistent_data_base->m_entries[index].GetData();
    }

    T *GetEntryByRight(const std::string &right) const
    {

        int index = m_volatile_map.FindIndexViaRightKey(right);
        if (index == INVALID)
        {

            return NULL;
        }
        return m_raw_persistent_data_base->m_entries[index].GetData();
    }

    unsigned long GenerateLeftKey(void)
    {
        return ++m_raw_persistent_data_base->m_left_key_counter;
    }
};

#endif // MYDB_H