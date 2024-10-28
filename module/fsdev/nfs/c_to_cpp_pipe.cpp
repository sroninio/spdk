#include "c_to_cpp_pipe.h"

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

        size_t full_size = sizeof(PersistentMap<struct NfsFsdevEntry>);
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

    bool InsertEntry(void *data_base, struct NfsFsdevEntry *entry, unsigned long left, struct nfs_fh3 *right)
    {
        PersistentMap<struct NfsFsdevEntry> *db = static_cast<PersistentMap<struct NfsFsdevEntry> *>(data_base);
        std::string_view temp(right->data.data_val, right->data.data_len);
        return db->InsertEntry(entry, left, temp);
    }

    bool UpdateEntryByLeft(void *data_base, struct NfsFsdevEntry *entry, unsigned long left)
    {
        PersistentMap<struct NfsFsdevEntry> *db = static_cast<PersistentMap<struct NfsFsdevEntry> *>(data_base);
        return db->UpdateEntryByLeft(entry, left);
    }

    bool UpdateEntryByRight(void *data_base, struct NfsFsdevEntry *entry, struct nfs_fh3 *right)
    {
        PersistentMap<struct NfsFsdevEntry> *db = static_cast<PersistentMap<struct NfsFsdevEntry> *>(data_base);
        std::string_view temp(right->data.data_val, right->data.data_len);
        return db->UpdateEntryByRight(entry, temp);
    }

    bool RemoveEntryByLeft(void *data_base, unsigned long left)
    {
        PersistentMap<struct NfsFsdevEntry> *db = static_cast<PersistentMap<struct NfsFsdevEntry> *>(data_base);
        return db->RemoveEntryByLeft(left);
    }

    bool RemoveEntryByRight(void *data_base, struct nfs_fh3 *right)
    {
        PersistentMap<struct NfsFsdevEntry> *db = static_cast<PersistentMap<struct NfsFsdevEntry> *>(data_base);
        std::string_view temp(right->data.data_val, right->data.data_len);
        return db->RemoveEntryByRight(temp);
    }

    struct NfsFsdevEntry GetEntryByLeft(void *data_base, unsigned long left)
    {
        PersistentMap<struct NfsFsdevEntry> *db = static_cast<PersistentMap<struct NfsFsdevEntry> *>(data_base);
        struct NfsFsdevEntry *entry = db->GetEntryByLeft(left);
        return *entry;
    }

    struct NfsFsdevEntry GetEntryByRight(void *data_base, struct nfs_fh3 *right)
    {
        PersistentMap<struct NfsFsdevEntry> *db = static_cast<PersistentMap<struct NfsFsdevEntry> *>(data_base);
        std::string_view temp(right->data.data_val, right->data.data_len);
        struct NfsFsdevEntry *entry = db->GetEntryByRight(temp);
        return *entry;
    }
}