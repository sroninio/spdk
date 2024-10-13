rm btest_db.bin
gcc -o test_persistent_map test_persistent_map.c persistent_map.c mymap.cpp -lstdc++
./test_persistent_map