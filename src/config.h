#ifndef RADIX_CONFIG_H
#define RADIX_CONFIG_H

#include <string>
#include <vector>

namespace Radix {

/**
 * @brief Configuration structure for Radix Blockchain
 * 
 * Contains all configurable parameters for running a Radix node.
 * Values can be loaded from JSON config file and overridden by CLI arguments.
 */
struct RadixConfig {
    // Network settings
    int port = 8080;
    std::string connect_peer = "";
    int max_connections = 50;
    
    // Mining settings
    bool mining_enabled = false;
    std::string miner_address = "radix_miner_default";
    int mining_threads = 1;
    
    // RPC settings
    bool rpc_enabled = false;
    int rpc_port = 8090;
    bool rpc_auth_required = true;
    std::string rpc_keys_file = "rpc_keys.json";
    int rpc_rate_limit = 100; // requests/minute per IP
    int rpc_rate_limit_auth = 1000; // requests/minute per authenticated token
    std::vector<std::string> rpc_ip_whitelist;
    
    // Blockchain settings
    std::string data_dir = "./data";
    int difficulty = 1;
    
    // Logging settings
    std::string log_dir = "./logs";
    std::string log_level = "info";  // trace, debug, info, warn, error, critical
    
    // Server mode
    bool server_mode = false;
};

/**
 * @brief Configuration Manager for loading and merging configs
 * 
 * Supports loading from JSON files and overriding with CLI arguments.
 * Priority: CLI args > config file > defaults
 */
class ConfigManager {
public:
    /**
     * @brief Load configuration from JSON file
     * @param filepath Path to JSON config file
     * @return RadixConfig with values from file (defaults for missing keys)
     * @throws std::runtime_error if file exists but is invalid JSON
     */
    static RadixConfig loadFromFile(const std::string& filepath);
    
    /**
     * @brief Override config with CLI arguments
     * @param argc Argument count
     * @param argv Argument values
     * @param defaults Base config to override (from file or default)
     * @return RadixConfig with CLI overrides applied
     */
    static RadixConfig loadFromArgs(int argc, char* argv[], const RadixConfig& defaults);
    
    /**
     * @brief Get default configuration
     * @return RadixConfig with all default values
     */
    static RadixConfig getDefaults();
};

} // namespace Radix

#endif // RADIX_CONFIG_H
