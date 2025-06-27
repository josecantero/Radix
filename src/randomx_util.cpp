#include "randomx_util.h"
#include <randomx.h>     // Asegúrate de que randomx.h esté incluido
#include <iomanip>       // Para std::hex, std::setw
#include <sstream>       // Para std::stringstream
#include <stdexcept>     // Para std::runtime_error
#include <vector>        // Para std::vector
#include <cstring>       // Para memcpy si es necesario

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
    // Orden de argumentos de randomx_create_vm ya estaba corregido
    vm = randomx_create_vm(flags, cache, dataset);
    if (!vm) {
        randomx_release_dataset(dataset);
        randomx_release_cache(cache);
        throw std::runtime_error("Failed to create RandomX VM.");
    }
}

// Implementación del método initCache
void RandomXContext::initCache(const std::vector<uint8_t>& seed) {
    if (!cache) {
        throw std::runtime_error("RandomX cache not allocated or initialized.");
    }
    randomx_init_cache(cache, seed.data(), seed.size());
}

// Implementación del método initDataset
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
        vm = nullptr; // Buenas prácticas: establece el puntero a nullptr después de liberarlo
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

// Implementación del método hash para std::vector<uint8_t>
RandomXHash RandomXContext::hash(const std::vector<uint8_t>& data) const {
    if (!vm) {
        throw std::runtime_error("RandomX VM not initialized.");
    }
    RandomXHash result;
    randomx_calculate_hash(vm, data.data(), data.size(), result.data());
    return result;
}

// Implementación del método hash para std::string (sobrecarga)
RandomXHash RandomXContext::hash(const std::string& data) const {
    // Convierte el string a std::vector<uint8_t> y luego calcula el hash
    std::vector<uint8_t> data_vec(data.begin(), data.end());
    return hash(data_vec); // Llama a la otra sobrecarga
}

// Función de utilidad para convertir un hash RandomX a una cadena hexadecimal.
std::string toHexString(const RandomXHash& hash) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : hash) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

// Función de utilidad para convertir un vector de bytes a una cadena hexadecimal.
std::string toHexString(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : bytes) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

// Implementación de la función para convertir un string hexadecimal a RandomXHash (std::array)
void fromHexString(const std::string& hexString, RandomXHash& hash) {
    if (hexString.length() % 2 != 0) {
        throw std::runtime_error("La cadena hexadecimal tiene una longitud impar.");
    }
    if (hexString.length() / 2 != hash.size()) {
        throw std::runtime_error("La longitud de la cadena hexadecimal no coincide con el tamaño del hash.");
    }

    for (size_t i = 0; i < hexString.length(); i += 2) {
        std::string byteString = hexString.substr(i, 2);
        hash[i / 2] = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
    }
}

// Implementación de la función para convertir un string hexadecimal a std::vector<uint8_t>
void fromHexString(const std::string& hexString, std::vector<uint8_t>& bytes) {
    if (hexString.length() % 2 != 0) {
        throw std::runtime_error("La cadena hexadecimal tiene una longitud impar.");
    }
    bytes.clear();
    bytes.reserve(hexString.length() / 2); // Pre-reservar espacio para evitar reasignaciones
    for (size_t i = 0; i < hexString.length(); i += 2) {
        std::string byteString = hexString.substr(i, 2);
        bytes.push_back(static_cast<uint8_t>(std::stoul(byteString, nullptr, 16)));
    }
}

} // namespace Radix
