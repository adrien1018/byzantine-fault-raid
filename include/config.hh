#ifndef _FILESYS_CONFIG_HH
#define _FILESYS_CONFIG_HH

#include <cstdint>
#include <string>
#include <vector>

struct Config {
    uint32_t num_malicious;
    uint32_t num_faulty;
    std::vector<std::string> servers;
};

Config ParseConfig(const std::string &config_file);

#endif