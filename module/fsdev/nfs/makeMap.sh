g++ -shared -fPIC volatile_map.cpp -o libvolatile_map.so
#gcc -shared -fPIC persistent_map.c -L. -lmymap -o libpersistent_map.so
# Compile persistent_map.c with SPDK include path
gcc -shared -fPIC persistent_map.c -L. -lvolatile_map -I/home/DocaSpdk/spdk/include -o libpersistent_map.so