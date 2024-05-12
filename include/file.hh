#ifndef _FILESYS_FILE_HH
#define _FILESYS_FILE_HH

#include <string>

struct File {
    std::string owner;
    std::string public_key; /* TODO: fix key type. */
    uint32_t version;
};

#endif