#ifndef MYDB_H
#define MYDB_H

#include <iostream>
#include <unordered_map>
#include <cstring>
#include <string>
#include <cassert>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <stdbool.h>
#include <spdk/barrier.h>
#include <boost/bimap.hpp>
#include <boost/bimap/unordered_set_of.hpp>
#include <boost/functional/hash.hpp>
#include <vector>
#include <memory>
#include <algorithm>

#define MAGIC_NUMBER 0x12345678
#define END_OF_LIST -1
#define MAX_SIZE_DB 1000000
#define INVALID -1
#define NA -2

struct Right
{
    right index
}

struct Left
{
    Left index
}

class VolatileMap
{
private:
    std::unordered_map<left, Right>
        std::unordered_map<right, Left>

            // BOOST::BIMAP
            std::map<(int, std::string_view)> m_map;

public:
    VolatileMap(some_param) : m_map(some)
    {
        // To Do
    }

    VolatileMap(const VolatileMap &other) = delete;
    VolatileMap &operator=(const VolatileMap &other) = delete;
    ~VolatileMap() = delete;

    bool insert(unsigned long left, const std::string_view &right, unsigned long persistent_db_index)
    {
        // TO DO
        return true;
    }

    bool remove_by_left_key(unsigned long left)
    {
        // TO DO
        return true;
    }

    bool remove_by_right_key(unsigned long right)
    {
        // TO DO
        return true;
    }

    unsigned long find_index_via_left_key(unsigned long key) const
    {
        // TO DO
        return 1;
    }

    unsigned long find_index_via_right_key(std::string_view right) const
    {
        // TO DO
        return true;
    }
};

template <typename T>
class Entry
{
private:
    int m_next;
    unsigned long m_left;
    std::string_view m_right;
    T m_data[2];
    int m_version;

public:
    Entry(int next, unsigned long left, std::string_view right, const T &value) : m_next(next), m_left(left), m_right(right), m_version(0)
    {
        m_data[0] = value;
        m_data[1] = value;
    }

    ~Entry() = delete;

    void Update(const T &new_version)
    {
        memcpy(&(m_data[(version + 1) % 2]), &new_version, sizeof(T));
        spdk_compiler_barrier();
        m_version = (m_version + 1) % 2;
    }

    T *GetData(void)
    {
        return &m_data[version];
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
    std::string_view GetRightKey()
    {
        return m_right;
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

        for (size_t i = 0; i < MAX_SIZE_DB; ++i)
        {
            if (!is_free_arr[i])
            {
                unsigned long left = m_raw_persistent_data_base->m_entries[i].GetLeftKey();
                std::string_view right = m_raw_persistent_data_base->m_entries[i].GetRightKey();
                m_volatile_map.insert(left, right, i);
            }
        }
    }

public:
    PersistentMap(struct RawPersistentDataBase *pers_db) : m_volatile_map(), m_raw_persistent_data_base(pers_db)
    {
        if (m_raw_persistent_data_base->m_magic != MAGIC_NUMBER)
        {
            Init();
            spdk_compiler_barrier();
        }
        else
        {
            Restore();
        }
    }

    PersistentMap(const PersistentMap &other) = delete;
    PersistentMap &operator=(const PersistentMap &other) = delete;
    ~PersistentMap() = delete;

    // will return false if and only if there is already entry like this
    bool InsertEntry(const T &entry, unsigned long left, const std::string_view &right)
    {
        int index1 = m_volatile_map.find_index_via_left_key(left);
        int index2 = m_volatile_map.find_index_via_right_key(right);

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
        int index = m_volatile_map.find_index_via_left_key(left);
        if (index == INVALID)
        {
            return false;
        }

        m_raw_persistent_data_base->m_entries[index].Update(entry);
        spdk_compiler_barrier();

        return true;
    }

    bool UpdateEntryByRight(const T &entry, const std::string_view &right)
    {
        int index = m_volatile_map.find_index_via_right_key(right);
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
        int index = m_volatile_map.find_index_via_left_key(left);
        if (index == INVALID)
        {
            return false;
        }

        if (m_volatile_map.remove_by_left_key(left) == false)
        {
            return false;
        }

        m_raw_persistent_data_base->m_entries[index].SetNext(m_raw_persistent_data_base->m_free_list_head);

        spdk_compiler_barrier();
        m_raw_persistent_data_base->m_free_list_head = index;
        spdk_compiler_barrier();

        return true;
    }

    bool RemoveEntryByRight(const std::string_view &right)
    {
        int index = m_volatile_map.find_index_via_right_key(right);
        if (index == INVALID)
        {
            return false;
        }

        if (m_volatile_map.remove_by_right_key(right) == false)
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
        int index = m_volatile_map.find_index_via_left_key(left);
        if (index == INVALID)
        {
            return NULL;
        }
        return m_raw_persistent_data_base->m_entries[index].GetData();
    }

    T *GetEntryByRight(const std::string_view &right) const
    {
        int index = m_volatile_map.find_index_via_right_key(right);
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