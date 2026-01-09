#include "ApiKeyManager.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <random>
#include <ctime>
#include "nlohmann/json.hpp"

using json = nlohmann::json;

namespace Soverx {

std::string ApiKeyManager::generateApiKey() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    std::stringstream ss;
    // Generate 4 * 64-bit integers = 256 bits of entropy
    for (int i = 0; i < 4; ++i) {
        ss << std::hex << std::setfill('0') << std::setw(16) << dis(gen);
    }
    return ss.str();
}

void ApiKeyManager::listKeys(const std::string& keysFile) {
    std::ifstream file(keysFile);
    if (!file.is_open()) {
        std::cerr << "Could not open keys file: " << keysFile << std::endl;
        return;
    }

    try {
        json j;
        file >> j;
        
        if (!j.contains("keys") || !j["keys"].is_array()) {
            std::cout << "No keys found or invalid file format." << std::endl;
            return;
        }

        std::cout << std::left << std::setw(66) << "API Key" 
                  << std::setw(20) << "Name" 
                  << std::setw(10) << "Status" 
                  << "Created" << std::endl;
        std::cout << std::string(110, '-') << std::endl;

        for (const auto& item : j["keys"]) {
            std::string key = item.value("key", "unknown");
            std::string name = item.value("name", "unnamed");
            bool revoked = item.value("revoked", false);
            uint64_t created = item.value("created_at", 0);
            
            std::time_t createdTime = (std::time_t)created;
            char buffer[20];
            std::strftime(buffer, 20, "%Y-%m-%d", std::localtime(&createdTime));

            std::cout << std::left << std::setw(66) << key
                      << std::setw(20) << name
                      << std::setw(10) << (revoked ? "REVOKED" : "ACTIVE")
                      << buffer << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error reading keys file: " << e.what() << std::endl;
    }
}

std::string ApiKeyManager::createKey(const std::string& name, const std::string& outputFile) {
    std::string key = generateApiKey();
    uint64_t now = std::time(nullptr);
    
    json root;
    
    // Load existing
    std::ifstream fileIn(outputFile);
    if (fileIn.is_open()) {
        try {
            fileIn >> root;
        } catch (...) {
            // Ignore error, start fresh
            root = json::object();
        }
    }
    
    if (!root.contains("keys") || !root["keys"].is_array()) {
        root["keys"] = json::array();
    }
    
    json newKey = {
        {"key", key},
        {"name", name},
        {"created_at", now},
        {"last_used", now},
        {"revoked", false},
        {"request_count", 0}
    };
    
    root["keys"].push_back(newKey);
    
    std::ofstream fileOut(outputFile);
    fileOut << std::setw(2) << root << std::endl;
    
    return key;
}

bool ApiKeyManager::revokeKey(const std::string& targetKey, const std::string& keysFile) {
    std::ifstream fileIn(keysFile);
    if (!fileIn.is_open()) return false;
    
    json root;
    try {
        fileIn >> root;
    } catch (...) {
        return false;
    }
    
    if (!root.contains("keys")) return false;
    
    bool found = false;
    for (auto& item : root["keys"]) {
        if (item.value("key", "") == targetKey) {
            item["revoked"] = true;
            found = true;
            break;
        }
    }
    
    if (found) {
        std::ofstream fileOut(keysFile);
        fileOut << std::setw(2) << root << std::endl;
    }
    
    return found;
}

bool ApiKeyManager::loadKeys(const std::string& keysFile, std::unordered_map<std::string, ApiKeyInfo>& apiKeys) {
    std::ifstream file(keysFile);
    if (!file.is_open()) return false;
    
    try {
        json root;
        file >> root;
        
        if (!root.contains("keys") || !root["keys"].is_array()) return false;
        
        for (const auto& item : root["keys"]) {
            ApiKeyInfo info;
            info.key = item.value("key", "");
            if (info.key.empty()) continue;
            
            info.name = item.value("name", "");
            info.createdAt = item.value("created_at", 0);
            info.lastUsed = item.value("last_used", 0);
            info.revoked = item.value("revoked", false);
            info.requestCount = item.value("request_count", 0);
            
            apiKeys[info.key] = info;
        }
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace Soverx
