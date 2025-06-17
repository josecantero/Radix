#include "randomx_util.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm> // Para std::min

namespace Radix {

RandomXContext::RandomXContext() : cache(nullptr), vm(nullptr), initialized(false) {}

RandomXContext::~RandomXContext() {
    if (vm) {
        randomx_destroy_vm(vm);
    }
    if (cache) {
        randomx_release_cache(cache);
    }
}

void RandomXContext::initialize(const std::vector<uint8_t>& seed) {
    if (initialized) {
        // Liberar recursos existentes si ya fue inicializado con otra semilla
        if (vm) randomx_destroy_vm(vm);
        if (cache) randomx_release_cache(cache);
        vm = nullptr;
        cache = nullptr;
        initialized = false;
    }

    randomx_flags flags = RANDOMX_FLAG_DEFAULT; // RANDOMX_FLAG_JIT | RANDOMX_FLAG_HARD_AES;

    // Asignar y inicializar el caché
    cache = randomx_alloc_cache(flags);
    if (!cache) {
        throw std::runtime_error("Error: No se pudo asignar RandomX cache.");
    }
    randomx_init_cache(cache, seed.data(), seed.size());

    // Asignar y inicializar la VM
    vm = randomx_create_vm(flags, cache, nullptr); // Dataset no es necesario para PoW simple
    if (!vm) {
        randomx_release_cache(cache); // Limpiar si la VM falla
        throw std::runtime_error("Error: No se pudo asignar RandomX VM.");
    }
    initialized = true;
}

RandomXHash RandomXContext::calculateHash(const std::vector<uint8_t>& data, const std::vector<uint8_t>& seed) {
    // Re-inicializar si la semilla ha cambiado (comportamiento simplificado)
    // En un blockchain real, la semilla de RandomX se deriva del bloque anterior
    // o un mecanismo más sofisticado para evitar recalcular cache/VM constantemente.
    // Para esta etapa, si la semilla es diferente, reinicializamos.
    // Una implementación más robusta usaría un mecanismo para cambiar la semilla sin re-crear cache/VM
    // si la "semilla real" (como el hash del bloque anterior) no cambia drásticamente.
    initialize(seed); // Reinicializa con la nueva semilla si es necesario

    RandomXHash hash;
    randomx_calculate_hash(vm, data.data(), data.size(), hash.data());
    return hash;
}

std::string toHexString(const RandomXHash& hash) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : hash) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

RandomXHash fromHexString(const std::string& hexString) {
    RandomXHash hash;
    if (hexString.length() != RANDOMX_HASH_SIZE * 2) {
        // Podrías lanzar una excepción o manejar el error
        std::cerr << "Advertencia: Longitud de cadena hexadecimal incorrecta para RandomXHash." << std::endl;
        std::fill(hash.begin(), hash.end(), 0); // Rellenar con ceros
        return hash;
    }

    for (size_t i = 0; i < RANDOMX_HASH_SIZE; ++i) {
        std::string byteString = hexString.substr(i * 2, 2);
        hash[i] = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
    }
    return hash;
}

} // namespace Radix