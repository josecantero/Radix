#include "randomx_util.h"
#include <randomx.h>     // Make sure randomx.h is included
#include <iomanip>       // For std::hex, std::setw
#include <sstream>       // For std::stringstream
#include <stdexcept>     // For std::runtime_error
#include <vector>        // For std::vector
#include <cstring>       // For memcpy if necessary

namespace Radix {

RandomXContext::RandomXContext() : flags(RANDOMX_FLAG_DEFAULT), vm(nullptr), cache(nullptr), dataset(nullptr) {
    // Determine the optimal flags for the current CPU
    flags = randomx_flags();

    // Allocate memory for the cache
    cache = randomx_alloc_cache(flags);
    if (!cache) {
        throw std::runtime_error("Failed to allocate RandomX cache.");
    }

    // Allocate memory for the dataset
    dataset = randomx_alloc_dataset(flags);
    if (!dataset) {
        randomx_release_cache(cache);
        throw std::runtime_error("Failed to allocate RandomX dataset.");
    }

    // Allocate the VM (virtual machine)
    // Order of randomx_create_vm arguments was already corrected
    vm = randomx_create_vm(flags, cache, dataset);
    if (!vm) {
        randomx_release_dataset(dataset);
        randomx_release_cache(cache);
        throw std::runtime_error("Failed to create RandomX VM.");
    }
}

// Implementation of initCache method
void RandomXContext::initCache(const std::vector<uint8_t>& seed) {
    if (!cache) {
        throw std::runtime_error("RandomX cache not allocated or initialized.");
    }
    randomx_init_cache(cache, seed.data(), seed.size());
}

// Implementation of initDataset method
void RandomXContext::initDataset() {
    if (!dataset || !cache) {
        throw std::runtime_error("RandomX dataset or cache not allocated or initialized.");
    }

    // Initialize the entire dataset at once using randomx_init_dataset.
    // This addresses the "not declared" error for randomx_init_dataset_item.
    unsigned long dataset_item_count_val = randomx_dataset_item_count();
    randomx_init_dataset(dataset, cache, 0, dataset_item_count_val);
}

RandomXContext::~RandomXContext() {
    if (vm) {
        randomx_destroy_vm(vm);
        vm = nullptr; // Good practice: set pointer to nullptr after freeing
    }
    if (dataset) {
        randomx_release_dataset(dataset);
        dataset = nullptr;
    }
    if (cache) {
        randomx_release_cache(cache);
        cache = nullptr;
    }
}

// Implementation of hash method for std::vector<uint8_t>
RandomXHash RandomXContext::hash(const std::vector<uint8_t>& data) const {
    if (!vm) {
        throw std::runtime_error("RandomX VM not initialized.");
    }
    RandomXHash result;
    randomx_calculate_hash(vm, data.data(), data.size(), result.data());
    return result;
}

// Implementation of hash method for std::string (overload)
RandomXHash RandomXContext::hash(const std::string& data) const {
    // Convert string to std::vector<uint8_t> and then calculate hash
    std::vector<uint8_t> data_vec(data.begin(), data.end());
    return hash(data_vec); // Call the other overload
}

// Utility function to convert a RandomX hash to a hexadecimal string.
std::string toHexString(const RandomXHash& hash) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : hash) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

// Utility function to convert a byte vector to a hexadecimal string.
std::string toHexString(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : bytes) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

// Implementation of fromHexString for RandomXHash
void fromHexString(const std::string& hexString, RandomXHash& hash) {
    if (hexString.length() != hash.size() * 2) {
        throw std::runtime_error("Hex string length does not match RandomXHash size.");
    }
    for (size_t i = 0; i < hash.size(); ++i) {
        hash[i] = static_cast<uint8_t>(std::stoul(hexString.substr(i * 2, 2), nullptr, 16));
    }
}

// Implementation of fromHexString for std::vector<uint8_t>
void fromHexString(const std::string& hexString, std::vector<uint8_t>& bytes) {
    if (hexString.length() % 2 != 0) {
        throw std::runtime_error("Hex string has odd length.");
    }
    bytes.resize(hexString.length() / 2);
    for (size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<uint8_t>(std::stoul(hexString.substr(i * 2, 2), nullptr, 16));
    }
}

} // namespace Radix
