#include "c_to_cpp_pipe.h"

void *db;

//===== left:

void test_insert_and_retrival_left()
{
    printf("\n\033[1;33m=== test_insert_and_retrival_left ===\033[0m\n");
    struct NfsFsdevEntry entry = {0};
    entry.inode = 17;
    entry.ref_count = 1;
    entry.fh.data.data_val[0] = 'h';
    entry.fh.data.data_val[1] = 'i';
    entry.fh.data.data_len = 2;

    if (insert_entry(db, &entry, entry.inode, &entry.fh))
    {
        printf("Inserted succesefuly to the map \n");
    }
    else
    {
        printf("Fail to insert \n");
        return;
    }

    const struct NfsFsdevEntry *e = get_entry_by_left(db, entry.inode);
    if (e == NULL)
    {
        printf("Not found \n");
        return;
    }
    else
    {
        printf("Found Entry: inode=[%ld], ref_count=[%ld], fh.data.len =[%d], fh.data = [", e->inode, e->ref_count, e->fh.data.data_len);
        for (int i = 0; i < e->fh.data.data_len; ++i)
        {
            printf("%c", e->fh.data.data_val[i]);
        }
        printf("]\n");
    }
    printf("\033[0;32m============= ✓ Correct =============\033[0m\n\n");
}

void test_insert_and_retrival_and_update_retrival_left()
{
    printf("\n\033[1;33m=== test_insert_and_retrival_and_update_retrival_left ===\033[0m\n");
    struct NfsFsdevEntry entry = {0};
    entry.inode = 19;
    entry.ref_count = 1;
    entry.fh.data.data_val[0] = 'h';
    entry.fh.data.data_val[1] = 'e';
    entry.fh.data.data_val[2] = 'l';
    entry.fh.data.data_val[3] = 'l';
    entry.fh.data.data_val[4] = 'o';
    entry.fh.data.data_len = 5;

    if (insert_entry(db, &entry, entry.inode, &entry.fh))
    {
        printf("Inserted succesefuly to the map \n");
    }
    else
    {
        printf("Fail to insert \n");
        return;
    }

    const struct NfsFsdevEntry *e = get_entry_by_left(db, entry.inode);
    if (e == NULL)
    {
        printf("Not found \n");
    }
    else
    {
        printf("Found Entry: inode=[%ld], ref_count=[%ld], fh.data.len =[%d], fh.data = [", e->inode, e->ref_count, e->fh.data.data_len);
        for (int i = 0; i < e->fh.data.data_len; ++i)
        {
            printf("%c", e->fh.data.data_val[i]);
        }
        printf("]\n");
    }

    printf("Now we are calling Update....\n");
    struct NfsFsdevEntry entry2 = {0};
    entry2.inode = 19;
    entry2.ref_count = 3222;
    entry2.fh.data.data_val[0] = 'h';
    entry2.fh.data.data_val[1] = 'e';
    entry2.fh.data.data_val[2] = 'l';
    entry2.fh.data.data_val[3] = 'l';
    entry2.fh.data.data_val[4] = 'o';
    entry2.fh.data.data_len = 5;
    if (update_entry_by_left(db, &entry2, entry2.inode))
    {
        const struct NfsFsdevEntry *e = get_entry_by_left(db, entry2.inode);
        if (e == NULL)
        {
            printf("Not found \n");
        }
        else
        {
            printf("Found Entry: inode=[%ld], ref_count=[%ld], fh.data.len =[%d], fh.data = [", e->inode, e->ref_count, e->fh.data.data_len);
            for (int i = 0; i < e->fh.data.data_len; ++i)
            {
                printf("%c", e->fh.data.data_val[i]);
            }
            printf("]\n");
        }
    }
    else
    {
        printf("Error in update \n");
        return;
    }
    printf("\033[0;32m============= ✓ Correct =============\033[0m\n\n");
}

void test_insert_and_remove_left()
{
    printf("\n\033[1;33m=== test_insert_and_remove_left ===\033[0m\n");
    struct NfsFsdevEntry entry = {0};
    entry.inode = 22;
    entry.ref_count = 1;
    entry.fh.data.data_val[0] = 'h';
    entry.fh.data.data_val[1] = 'i';
    entry.fh.data.data_val[2] = 'i';
    entry.fh.data.data_val[3] = 'i';

    entry.fh.data.data_len = 4;

    if (insert_entry(db, &entry, entry.inode, &entry.fh))
    {
        printf("Inserted succesefuly to the map \n");
    }
    else
    {
        printf("Fail to insert \n");
        return;
    }

    if (!remove_entry_by_left(db, 22))
    {
        printf("Error");
        return;
    }

    const struct NfsFsdevEntry *e = get_entry_by_left(db, 22);
    if (e == NULL)
    {
        printf("Not found - as needed \n");
    }
    else
    {
        printf("Error : found this entry\n");
        printf("Found Entry: inode=[%ld], ref_count=[%ld], fh.data.len =[%d], fh.data = [", e->inode, e->ref_count, e->fh.data.data_len);
        for (int i = 0; i < e->fh.data.data_len; ++i)
        {
            printf("%c", e->fh.data.data_val[i]);
        }
        printf("]\n");
        return;
    }

    printf("\033[0;32m============= ✓ Correct =============\033[0m\n\n");
}

void restore_data_base_left()
{
    printf("\n\033[1;33m=== restore_data_base_left ===\033[0m\n");

    void *db2 = allocate_and_init_map("/Users/aevdaev/Desktop/spdk/module/fsdev/nfs/testGeneric.txt");
    db = db2;
    const struct NfsFsdevEntry *e = get_entry_by_left(db2, 19);
    if (e == NULL)
    {
        printf("Not found \n");
    }
    else
    {
        printf("Found Entry: inode=[%ld], ref_count=[%ld], fh.data.len =[%d], fh.data = [", e->inode, e->ref_count, e->fh.data.data_len);
        for (int i = 0; i < e->fh.data.data_len; ++i)
        {
            printf("%c", e->fh.data.data_val[i]);
        }
        printf("]\n");
    }

    e = get_entry_by_left(db2, 17);
    if (e == NULL)
    {
        printf("Not found \n");
    }
    else
    {
        printf("Found Entry: inode=[%ld], ref_count=[%ld], fh.data.len =[%d], fh.data = [", e->inode, e->ref_count, e->fh.data.data_len);
        for (int i = 0; i < e->fh.data.data_len; ++i)
        {
            printf("%c", e->fh.data.data_val[i]);
        }
        printf("]\n");
    }

    e = get_entry_by_left(db2, 22);
    if (e == NULL)
    {
        printf("Not found - 22 as needed \n");
    }
    else
    {
        printf("Error : found this entry\n");
        printf("Found Entry: inode=[%ld], ref_count=[%ld], fh.data.len =[%d], fh.data = [", e->inode, e->ref_count, e->fh.data.data_len);
        for (int i = 0; i < e->fh.data.data_len; ++i)
        {
            printf("%c", e->fh.data.data_val[i]);
        }
        printf("]\n");
        return;
    }

    printf("\033[0;32m============= ✓ Correct =============\033[0m\n\n");
}

//===== right:
void test_insert_and_retrival_right()
{
    printf("\n\033[1;33m=== test_insert_and_retrival_right ===\033[0m\n");
    struct NfsFsdevEntry entry = {0};
    entry.inode = 30;
    entry.ref_count = 1;
    entry.fh.data.data_val[0] = 'a';
    entry.fh.data.data_val[1] = 'b';
    entry.fh.data.data_len = 2;

    if (insert_entry(db, &entry, entry.inode, &entry.fh))
    {
        printf("Inserted succesefuly to the map \n");
    }
    else
    {
        printf("Fail to insert \n");
        return;
    }

    const struct NfsFsdevEntry *e = get_entry_by_right(db, &entry.fh);
    if (e == NULL)
    {
        printf("Not found \n");
        return;
    }
    else
    {
        printf("Found Entry: inode=[%ld], ref_count=[%ld], fh.data.len =[%d], fh.data = [", e->inode, e->ref_count, e->fh.data.data_len);
        for (int i = 0; i < e->fh.data.data_len; ++i)
        {
            printf("%c", e->fh.data.data_val[i]);
        }
        printf("]\n");
    }
    printf("\033[0;32m============= ✓ Correct =============\033[0m\n\n");
}

void test_insert_and_retrival_and_update_retrival_right()
{
    printf("\n\033[1;33m=== test_insert_and_retrival_and_update_retrival_right ===\033[0m\n");
    struct NfsFsdevEntry entry = {0};
    entry.inode = 31;
    entry.ref_count = 1;
    entry.fh.data.data_val[0] = 'h';
    entry.fh.data.data_val[1] = 'e';
    entry.fh.data.data_val[2] = 'l';
    entry.fh.data.data_val[3] = 'l';
    entry.fh.data.data_val[4] = 'o';
    entry.fh.data.data_val[5] = 'o';
    entry.fh.data.data_val[6] = 'o';

    entry.fh.data.data_len = 7;

    if (insert_entry(db, &entry, entry.inode, &entry.fh))
    {
        printf("Inserted succesefuly to the map \n");
    }
    else
    {
        printf("Fail to insert \n");
        return;
    }

    const struct NfsFsdevEntry *e = get_entry_by_right(db, &entry.fh);
    if (e == NULL)
    {
        printf("\033[0;31mError Not found \033[0m\n");
    }
    else
    {
        printf("Found Entry: inode=[%ld], ref_count=[%ld], fh.data.len =[%d], fh.data = [", e->inode, e->ref_count, e->fh.data.data_len);
        for (int i = 0; i < e->fh.data.data_len; ++i)
        {
            printf("%c", e->fh.data.data_val[i]);
        }
        printf("]\n");
    }

    printf("Now we are calling Update....\n");
    struct NfsFsdevEntry entry2 = {0};
    entry2.inode = 31;
    entry2.ref_count = 3;
    entry2.fh.data.data_val[0] = 'h';
    entry2.fh.data.data_val[1] = 'e';
    entry2.fh.data.data_val[2] = 'l';
    entry2.fh.data.data_val[3] = 'l';
    entry2.fh.data.data_val[4] = 'o';
    entry2.fh.data.data_val[5] = 'o';
    entry2.fh.data.data_val[6] = 'o';
    entry2.fh.data.data_len = 7;

    if (update_entry_by_right(db, &entry2, &entry2.fh))
    {
        const struct NfsFsdevEntry *e = get_entry_by_right(db, &entry2.fh);
        if (e == NULL)
        {
            printf("\033[0;31mError Not found\033[0m\n");
        }
        else
        {
            printf("Found Entry: inode=[%ld], ref_count=[%ld], fh.data.len =[%d], fh.data = [", e->inode, e->ref_count, e->fh.data.data_len);
            for (int i = 0; i < e->fh.data.data_len; ++i)
            {
                printf("%c", e->fh.data.data_val[i]);
            }
            printf("]\n");
        }
    }
    else
    {
        printf("\033[0;31mError in update\033[0m\n");

        return;
    }
    printf("\033[0;32m============= ✓ Correct =============\033[0m\n\n");
}

void test_insert_and_remove_right()
{
    printf("\n\033[1;33m=== test_insert_and_remove_right ===\033[0m\n");
    struct NfsFsdevEntry entry = {0};
    entry.inode = 44;
    entry.ref_count = 1;
    entry.fh.data.data_val[0] = 'h';
    entry.fh.data.data_val[1] = 'x';
    entry.fh.data.data_val[2] = 'x';
    entry.fh.data.data_val[3] = 'i';
    entry.fh.data.data_len = 4;

    if (insert_entry(db, &entry, entry.inode, &entry.fh))
    {
        printf("Inserted succesefuly to the map \n");
    }
    else
    {
        printf("Fail to insert \n");
        return;
    }

    if (!remove_entry_by_right(db, &entry.fh))
    {
        printf("Error");
        return;
    }

    const struct NfsFsdevEntry *e = get_entry_by_right(db, &entry.fh);
    if (e == NULL)
    {
        printf("Not found - as needed \n");
    }
    else
    {
        printf("Error : found this entry\n");
        printf("Found Entry: inode=[%ld], ref_count=[%ld], fh.data.len =[%d], fh.data = [", e->inode, e->ref_count, e->fh.data.data_len);
        for (int i = 0; i < e->fh.data.data_len; ++i)
        {
            printf("%c", e->fh.data.data_val[i]);
        }
        printf("]\n");
        return;
    }

    printf("\033[0;32m============= ✓ Correct =============\033[0m\n\n");
}

void restore_data_base_left_and_right()
{
    printf("\n\033[1;33m=== restore_data_base_left_and_right ===\033[0m\n");

    void *db2 = db;
    db2 = allocate_and_init_map("/Users/aevdaev/Desktop/spdk/module/fsdev/nfs/testGeneric.txt");
    // problem with restore function !!

    const struct NfsFsdevEntry *e = get_entry_by_left(db2, 17);
    if (e == NULL)
    {
        printf("\033[0;31mError Not found\033[0m\n");
    }
    else
    {
        printf("Found Entry: inode=[%ld], ref_count=[%ld], fh.data.len =[%d], fh.data = [", e->inode, e->ref_count, e->fh.data.data_len);
        for (int i = 0; i < e->fh.data.data_len; ++i)
        {
            printf("%c", e->fh.data.data_val[i]);
        }
        printf("]\n");
    }

    e = get_entry_by_left(db2, 19);
    if (e == NULL)
    {
        printf("\033[0;31mError Not found\033[0m\n");
    }
    else
    {
        printf("Found Entry: inode=[%ld], ref_count=[%ld], fh.data.len =[%d], fh.data = [", e->inode, e->ref_count, e->fh.data.data_len);
        for (int i = 0; i < e->fh.data.data_len; ++i)
        {
            printf("%c", e->fh.data.data_val[i]);
        }
        printf("]\n");
    }

    e = get_entry_by_left(db2, 22);
    if (e == NULL)
    {
        printf("Not found - as needed \n");
    }
    else
    {
        printf("\033[0;31mError found\033[0m\n");

        printf("Found Entry: inode=[%ld], ref_count=[%ld], fh.data.len =[%d], fh.data = [", e->inode, e->ref_count, e->fh.data.data_len);
        for (int i = 0; i < e->fh.data.data_len; ++i)
        {
            printf("%c", e->fh.data.data_val[i]);
        }
        printf("]\n");
        return;
    }
    struct persistent_nfs_fh3 temp = {0};
    temp.data.data_len = 2;
    temp.data.data_val[0] = 'a';
    temp.data.data_val[1] = 'b';

    e = get_entry_by_right(db2, &temp);
    if (e == NULL)
    {
        printf("\033[0;31mError\033[0m\n");
    }
    else
    {
        printf("Found Entry: inode=[%ld], ref_count=[%ld], fh.data.len =[%d], fh.data = [", e->inode, e->ref_count, e->fh.data.data_len);
        for (int i = 0; i < e->fh.data.data_len; ++i)
        {
            printf("%c", e->fh.data.data_val[i]);
        }
        printf("]\n");
    }

    temp.data.data_len = 7;
    temp.data.data_val[0] = 'h';
    temp.data.data_val[1] = 'e';
    temp.data.data_val[2] = 'l';
    temp.data.data_val[3] = 'l';
    temp.data.data_val[4] = 'o';
    temp.data.data_val[5] = 'o';
    temp.data.data_val[6] = 'o';

    e = get_entry_by_right(db2, &temp);
    if (e == NULL)
    {
        printf("\033[0;31mError\033[0m\n");
    }
    else
    {
        printf("Found Entry: inode=[%ld], ref_count=[%ld], fh.data.len =[%d], fh.data = [", e->inode, e->ref_count, e->fh.data.data_len);
        for (int i = 0; i < e->fh.data.data_len; ++i)
        {
            printf("%c", e->fh.data.data_val[i]);
        }
        printf("]\n");
    }

    temp.data.data_len = 4;
    temp.data.data_val[0] = 'h';
    temp.data.data_val[1] = 'x';
    temp.data.data_val[2] = 'x';
    temp.data.data_val[3] = 'i';

    e = get_entry_by_right(db2, &temp);
    if (e == NULL)
    {
        printf("Not found as needed\n");
    }
    else
    {
        printf("\033[0;31mError Found deleted entry\033[0m\n");

        printf("Found Entry: inode=[%ld], ref_count=[%ld], fh.data.len =[%d], fh.data = [", e->inode, e->ref_count, e->fh.data.data_len);
        for (int i = 0; i < e->fh.data.data_len; ++i)
        {
            printf("%c", e->fh.data.data_val[i]);
        }
        printf("]\n");
        return;
    }

    printf("\033[0;32m============= ✓ Correct =============\033[0m\n\n");
}

int main(void)
{
    remove("/Users/aevdaev/Desktop/spdk/module/fsdev/nfs/testGeneric.txt");
    db = allocate_and_init_map("/Users/aevdaev/Desktop/spdk/module/fsdev/nfs/testGeneric.txt");

    test_insert_and_retrival_left();
    test_insert_and_retrival_and_update_retrival_left();
    test_insert_and_remove_left();
    restore_data_base_left();

    test_insert_and_retrival_right();
    test_insert_and_retrival_and_update_retrival_right();
    test_insert_and_remove_right();
    restore_data_base_left_and_right();

    return 1;
}