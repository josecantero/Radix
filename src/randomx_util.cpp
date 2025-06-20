#include "randomx_util.h"
#include <iostream>
#include <iomanip> // Para std::setw, std::setfill
#include <sstream> // Para std::stringstream
#include <vector> // Asegúrate de que está incluido para std::vector
#include <stdexcept> // Para std::runtime_error

namespace Radix {

RandomXContext::RandomXContext() : cache(nullptr), vm(nullptr) {
    // Generar una semilla fija o predeterminada para la inicialización del cache.
    // En una implementación real de una blockchain, esta semilla (o una semilla
    // derivada de datos del bloque anterior/cadena) podría ser más compleja.
    std::string seed_str = "RadixBlockchainSeed12345ForPoW"; // Una semilla de ejemplo
    std::vector<uint8_t> seed(seed_str.begin(), seed_str.end());

    // Crear el cache RandomX (puede tardar un poco y usar bastante RAM)
    // RANDOMX_FLAG_DEFAULT incluye flags como JIT e HASH_ALG
    cache = randomx_alloc_cache(RANDOMX_FLAG_DEFAULT);
    if (!cache) {
        // En un programa real, esto debería manejar el error de forma más elegante
        // (lanzar una excepción, registrar el error, etc.)
        std::cerr << "Error: No se pudo asignar el cache RandomX. Posiblemente falta de RAM." << std::endl;
        throw std::runtime_error("Failed to allocate RandomX cache.");
    }
    randomx_init_cache(cache, seed.data(), seed.size());

    // Crear la máquina virtual RandomX
    // El último argumento (dataset) es NULL porque el dataset se crea a partir del cache.
    vm = randomx_create_vm(RANDOMX_FLAG_DEFAULT, cache, NULL);
    if (!vm) {
        // Liberar el cache si la VM falla para evitar fugas de memoria.
        randomx_release_cache(cache);
        std::cerr << "Error: No se pudo crear la VM RandomX." << std::endl;
        throw std::runtime_error("Failed to create RandomX VM.");
    }
}

RandomXContext::~RandomXContext() {
    // Asegurarse de liberar la VM y el cache para evitar fugas de memoria.
    if (vm) {
        randomx_destroy_vm(vm);
        vm = nullptr;
    }
    if (cache) {
        randomx_release_cache(cache);
        cache = nullptr;
    }
}

// Implementación de calculateHash que solo toma los datos de entrada
RandomXHash RandomXContext::calculateHash(const std::vector<uint8_t>& data) {
    RandomXHash hash_array;
    // randomx_calculate_hash toma (randomx_vm* vm, const void* input, size_t input_size, void* output)
    randomx_calculate_hash(vm, data.data(), data.size(), hash_array.data());
    return hash_array;
}

// Función de utilidad para convertir un hash a string hexadecimal
std::string toHexString(const RandomXHash& hash) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : hash) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

} // namespace Radix