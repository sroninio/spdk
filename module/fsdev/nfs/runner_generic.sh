g++ -c -std=c++17 -g c_to_cpp_pipe.cpp -o c_to_cpp_pipe.o
gcc -c -g test_generic.c -o test_generic.o
g++ -g test_generic.o c_to_cpp_pipe.o -o test_generic