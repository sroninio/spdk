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
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"
#include "libnfs-raw-nfs.h"
#include <spdk/barrier.h>
#include <boost/bimap.hpp>
#include <boost/bimap/unordered_set_of.hpp>
#include <boost/functional/hash.hpp>

#define MAGIC_NUMBER 0x12345678

template <typename T>
class VolatileMapLeft
{
private:
    // To Do

public:
    // To Do
};

template <typename T>
class VolatileMapRight
{
private:
    // To Do

public:
    // To Do
};

template <typename T>
class VolatileMap
{
private:
    // BOOST::BIMAP
public:
    VolatileMap(void)
    {
        // To Do
    }

    VolatileMap(const VolatileMap &other) = delete;
    VolatileMap &operator=(const VolatileMap &other) = delete;

    ~VolatileMap()
    {
        // TO DO
    }

    unsigned long find_index_via_first_key(unsigned long key) const
    {
        // TO DO
        return 1;
    }

    bool insert_entry()
    {
        // TO DO
        return true;
    }

    bool remove_entry()
    {
        // TO DO
        return true;
    }

    unsigned long find_first_key_via_second_key() const
    {
        // TO DO
        return true;
    }
};

template <typename T>
class Entry
{
private:
    int m_auxiliary_index;
    T m_data;

public:
    Entry(int index, T value) : m_auxiliary_index(index), m_data(value) {}
};

template <typename T>
class PersistentMap
{
private:
    int m_magic;
    int m_free_list_head;
    size_t m_max_size;
    Entry<T> m_entries[]; // problem - not supported in cpp

public:
    PersistentMap(size_t max_size) : m_magic(MAGIC_NUMBER), m_free_list_head(0), m_max_size(max_size) {}
    PersistentMap(const PersistentMap &other) = delete;
    PersistentMap &operator=(const PersistentMap &other) = delete;
    ~PersistentMap() = delete;
};

template <typename T>
class DataBase
{
private:
    VolatileMap<T> *m_volatile_map;
    PersistentMap<T> *m_persistent_map;

public:
    DataBase(const std::string &filename, size_t dataBaseMaxSize)
    {
        // To Do - HOW ?
        return;
    }

    DataBase(const DataBase &other) = delete;
    DataBase &operator=(const DataBase &other) = delete;
    ~DataBase() = delete;

    bool InsertEntry(const Entry<T> &entry)
    {
        // To Do
        return true;
    }

    bool UpdateEntry(const Entry<T> &entry)
    {
        // To Do
        return true;
    }

    bool RemoveEntry(unsigned long key)
    {
        // To Do
        return true;
    }

    Entry<T> *GetEntry() const
    {
        // To Do
        return;
    }
};

#endif // MYDB_H