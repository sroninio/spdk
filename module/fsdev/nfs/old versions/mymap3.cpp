#include "mymap3.h"
#include <iostream>
#include <unordered_map>
#include <cstring>
#define CookieVerifierSize 8

// we should make another data strucutre for keeping track of each cookieverifer
// we get this as a return value in the funtion of readdir ,
// we get the field of cookie in the field offset of the input, but we don't keep track on the cookie verifier
//  for each inode we should keep a cookieVerifier (only direcotries will get to the point of inserting to this data structure !)

extern "C"
{
    void *create_my_map3(void)
    {
        return new std::unordered_map<unsigned long, char *>;
    }

    char *my_get3(void *map, unsigned long key)
    {
        std::unordered_map<unsigned long, char *> *my_map = (std::unordered_map<unsigned long, char *> *)map;
        return (*my_map)[key];
    }

    void my_insert3(void *map, unsigned long key, char *cookieverifier)
    {

        std::unordered_map<unsigned long, struct nfs_fh3> *my_map = (std::unordered_map<unsigned long, struct nfs_fh3> *)map;
        char *tmp = (char *)malloc(CookieVerifierSize * sizeof(char));
        for (int i = 0; i < CookieVerifierSize; ++i)
        {
            tmp[i] = cookieverifier[i];
        }
        (*my_map)[key] = tmp;
    }
}
