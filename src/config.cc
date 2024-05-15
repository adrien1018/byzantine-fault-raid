#include "config.h"

#include "toml.hh"

Config ParseConfig(const std::string& config_file) {
    Config config;
    const auto toml_config = toml::parse_file(config_file);

    config.num_malicious =
        toml_config["num_malicious"].value<uint32_t>().value();
    config.num_faulty = toml_config["num_faulty"].value<uint32_t>().value();
    config.stripe_size = toml_config["stripe_size"].value<uint32_t>().value();

    /* TODO: verify stripe size validity. */

    auto servers_toml = toml_config["servers"].as_array();

    for (const auto& server_str : *servers_toml) {
        config.servers.emplace_back(server_str.value<std::string>().value());
    }

    return config;
}