#include "config.h"

#include <toml++/toml.hpp>
#include <spdlog/spdlog.h>
#include "signature.h"

Config ParseConfig(const std::string& config_file) {
    Config config;
    const auto toml_config = toml::parse_file(config_file);

    config.num_malicious =
        toml_config["num_malicious"].value<uint32_t>().value();
    config.num_faulty = toml_config["num_faulty"].value<uint32_t>().value();
    config.block_size = toml_config["block_size"].value<uint32_t>().value();

    auto servers_toml = toml_config["servers"].as_array();
    for (const auto& server_str : *servers_toml) {
        config.servers.emplace_back(server_str.value<std::string>().value());
    }

    if (config.num_faulty < config.num_malicious * 2) {
        spdlog::error("num_faulty must be at least (2 * num_malicious)");
        exit(1);
    }
    if (config.num_faulty >= config.servers.size()) {
        spdlog::error("num_faulty must be less than the number of servers");
        exit(1);
    }
    if (config.servers.size() < config.num_malicious * 3 + 1) {
        spdlog::warn("Less than (num_malicious * 3 + 1) servers. Phantom files are possible.");
    }
    if (config.block_size <= SigningKey::kSignatureSize * config.servers.size()) {
        spdlog::error("block_size must be greater than (signature size * num_servers)");
        exit(1);
    }

    return config;
}
