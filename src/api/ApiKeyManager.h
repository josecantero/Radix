#ifndef RADIX_API_KEY_MANAGER_H
#define RADIX_API_KEY_MANAGER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include "../config.h"

namespace Radix {

struct ApiKeyInfo {
    std::string key;
    std::string name;
    uint64_t createdAt;
    uint64_t lastUsed;
    bool revoked;
    int requestCount;
};

class ApiKeyManager {
public:
    /**
     * @brief Generate a secure random API key (64 char hex)
     */
    static std::string generateApiKey();
    
    /**
     * @brief Create a new API key and append to keys file
     * @param name Name/description of the key owner
     * @param outputFile Path to json file
     * @return The generated key
     */
    static std::string createKey(const std::string& name, const std::string& outputFile);
    
    /**
     * @brief List all keys in the file to stdout
     */
    static void listKeys(const std::string& keysFile);
    
    /**
     * @brief Revoke an API key in the file
     */
    static bool revokeKey(const std::string& key, const std::string& keysFile);
    
    /**
     * @brief Load all keys from file into provided map
     * @param keysFile Path to json file
     * @param apiKeys Map to populate
     * @return true if successful
     */
    static bool loadKeys(const std::string& keysFile, std::unordered_map<std::string, ApiKeyInfo>& apiKeys);
};

} // namespace Radix

#endif // RADIX_API_KEY_MANAGER_H
