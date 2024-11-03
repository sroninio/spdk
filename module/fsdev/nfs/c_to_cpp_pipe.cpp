#include "c_to_cpp_pipe.h"
#include "generic_persistent_map.h"

extern "C"
{

    void *allocate_and_init_map(char *filename)
    {
        int fd = open(filename, O_RDWR | O_CREAT, 0666);
        if (fd == -1)
        {
            printf("Error: in opening file");
            return NULL;
        }

        size_t full_size = sizeof(RawPersistentDataBase<struct NfsFsdevEntry>);
        if (ftruncate(fd, full_size) == -1)
        {
            printf("Error: setting file size\n");
            close(fd);
            return NULL;
        }

        void *shmem = mmap(NULL, full_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (shmem == MAP_FAILED)
        {
            printf("Error: error mapping file\n");
            close(fd);
            return NULL;
        }

        return new PersistentMap<struct NfsFsdevEntry>(shmem);
    }

    bool insert_entry(void *data_base, struct NfsFsdevEntry *entry, unsigned long left, struct persistent_nfs_fh3 *right)
    {
        PersistentMap<struct NfsFsdevEntry> *db = static_cast<PersistentMap<struct NfsFsdevEntry> *>(data_base);
        std::string temp(right->data.data_val, right->data.data_len);
        return db->InsertEntry(*entry, left, temp);
    }

    bool update_entry_by_left(void *data_base, struct NfsFsdevEntry *entry, unsigned long left)
    {
        PersistentMap<struct NfsFsdevEntry> *db = static_cast<PersistentMap<struct NfsFsdevEntry> *>(data_base);
        return db->UpdateEntryByLeft(*entry, left);
    }

    bool update_entry_by_right(void *data_base, struct NfsFsdevEntry *entry, struct persistent_nfs_fh3 *right)
    {
        PersistentMap<struct NfsFsdevEntry> *db = static_cast<PersistentMap<struct NfsFsdevEntry> *>(data_base);
        std::string temp((char *)right->data.data_val, right->data.data_len);
        return db->UpdateEntryByRight(*entry, temp);
    }

    bool remove_entry_by_left(void *data_base, unsigned long left)
    {
        PersistentMap<struct NfsFsdevEntry> *db = static_cast<PersistentMap<struct NfsFsdevEntry> *>(data_base);
        return db->RemoveEntryByLeft(left);
    }

    bool remove_entry_by_right(void *data_base, struct persistent_nfs_fh3 *right)
    {
        PersistentMap<struct NfsFsdevEntry> *db = static_cast<PersistentMap<struct NfsFsdevEntry> *>(data_base);
        std::string temp((char *)right->data.data_val, right->data.data_len);
        return db->RemoveEntryByRight(temp);
    }

    struct NfsFsdevEntry get_entry_by_left(void *data_base, unsigned long left)
    {
        PersistentMap<struct NfsFsdevEntry> *db = static_cast<PersistentMap<struct NfsFsdevEntry> *>(data_base);
        return db->GetEntryByLeft(left);
    }

    struct NfsFsdevEntry get_entry_by_right(void *data_base, struct persistent_nfs_fh3 *right)
    {
        PersistentMap<struct NfsFsdevEntry> *db = static_cast<PersistentMap<struct NfsFsdevEntry> *>(data_base);
        std::string temp((char *)right->data.data_val, right->data.data_len);
        return db->GetEntryByRight(temp);
    }

    unsigned long generate_left_key(void *data_base)
    {
        PersistentMap<struct NfsFsdevEntry> *db = static_cast<PersistentMap<struct NfsFsdevEntry> *>(data_base);
        return db->GenerateLeftKey();
    }

    bool check_if_exist_by_left(void *data_base, unsigned long left)
    {
        PersistentMap<struct NfsFsdevEntry> *db = static_cast<PersistentMap<struct NfsFsdevEntry> *>(data_base);
        return db->CheckEntryExistByLeftKey(left);
    }

    bool check_if_exist_by_right(void *data_base, struct persistent_nfs_fh3 *right)
    {
        PersistentMap<struct NfsFsdevEntry> *db = static_cast<PersistentMap<struct NfsFsdevEntry> *>(data_base);
        std::string temp((char *)right->data.data_val, right->data.data_len);
        return db->CheckEntryExistByRightKey(temp);
    }
}
