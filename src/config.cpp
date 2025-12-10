#include "config.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include "nlohmann/json.hpp"

using json = nlohmann::json;

namespace Radix {

RadixConfig ConfigManager::getDefaults() {
    return RadixConfig(); // All defaults from struct initialization
}

RadixConfig ConfigManager::loadFromFile(const std::string& filepath) {
    RadixConfig config = getDefaults();
    
    std::ifstream file(filepath);
    if (!file.is_open()) {
        // File doesn't exist - return defaults
        std::cout << "ℹ️  Config file not found: " << filepath << " (using defaults)" << std::endl;
        return config;
    }
    
    try {
        json j;
        file >> j;
        
        // Network settings
        if (j.contains("network")) {
            auto network = j["network"];
            if (network.contains("port")) config.port = network["port"];
            if (network.contains("connect_peer")) config.connect_peer = network["connect_peer"];
            if (network.contains("max_connections")) config.max_connections = network["max_connections"];
        }
        
        // Mining settings
        if (j.contains("mining")) {
            auto mining = j["mining"];
            if (mining.contains("enabled")) config.mining_enabled = mining["enabled"];
            if (mining.contains("miner_address")) config.miner_address = mining["miner_address"];
            if (mining.contains("threads")) config.mining_threads = mining["threads"];
        }
        
        // RPC settings
        if (j.contains("rpc")) {
            auto rpc = j["rpc"];
            if (rpc.contains("enabled")) config.rpc_enabled = rpc["enabled"];
            if (rpc.contains("port")) config.rpc_port = rpc["port"];
            if (rpc.contains("auth_required")) config.rpc_auth_required = rpc["auth_required"];
            if (rpc.contains("keys_file")) config.rpc_keys_file = rpc["keys_file"];
            if (rpc.contains("rate_limit")) config.rpc_rate_limit = rpc["rate_limit"];
            if (rpc.contains("rate_limit_authenticated")) config.rpc_rate_limit_auth = rpc["rate_limit_authenticated"];
            if (rpc.contains("ip_whitelist") && rpc["ip_whitelist"].is_array()) {
                for (const auto& ip : rpc["ip_whitelist"]) {
                    config.rpc_ip_whitelist.push_back(ip);
                }
            }
        }
        
        // Blockchain settings
        if (j.contains("blockchain")) {
            auto blockchain = j["blockchain"];
            if (blockchain.contains("data_dir")) config.data_dir = blockchain["data_dir"];
            if (blockchain.contains("difficulty")) config.difficulty = blockchain["difficulty"];
        }
        
        std::cout << "✅ Configuration loaded from: " << filepath << std::endl;
        
    } catch (const json::exception& e) {
        throw std::runtime_error("Invalid JSON in config file: " + std::string(e.what()));
    }
    
    return config;
}

RadixConfig ConfigManager::loadFromArgs(int argc, char* argv[], const RadixConfig& defaults) {
    RadixConfig config = defaults;
    
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--server") == 0) {
            config.server_mode = true;
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            config.port = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "--connect") == 0 && i + 1 < argc) {
            config.connect_peer = argv[++i];
            config.server_mode = true;
        } else if (strcmp(argv[i], "--mine") == 0) {
            config.mining_enabled = true;
        } else if (strcmp(argv[i], "--miner-addr") == 0 && i + 1 < argc) {
            config.miner_address = argv[++i];
        } else if (strcmp(argv[i], "--rpc") == 0) {
            config.rpc_enabled = true;
        } else if (strcmp(argv[i], "--config") == 0) {
            // Skip, already handled
            if (i + 1 < argc) ++i;
        }
        // Note: CLI commands like --new-wallet, --get-balance, --send are handled separately in main.cpp
    }
    
    return config;
}

} // namespace Radix
