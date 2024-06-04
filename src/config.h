#ifndef _FILESYS_CONFIG_H
#define _FILESYS_CONFIG_H

#include <cstdint>
#include <string>
#include <vector>

struct Config {
    uint32_t num_malicious;
    uint32_t num_faulty;
    uint32_t block_size;
    std::vector<std::string> servers;
    std::string fuse_mount_point;
};

Config ParseConfig(const std::string &config_file);

#endif

