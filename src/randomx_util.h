#ifndef RANDOMX_UTIL_H
#define RANDOMX_UTIL_H

#include <string>
#include <vector>
#include <array>
#include <randomx.h> // Necesario para los tipos de RandomX

namespace Radix {

// Representación de un hash RandomX (32 bytes)
using RandomXHash = std::array<uint8_t, RANDOMX_HASH_SIZE>;

// Clase que maneja la inicialización y uso de RandomX VM y cache
class RandomXContext {
public:
    RandomXContext();
    ~RandomXContext();

    // Calcula el hash RandomX de los datos de entrada
    // La semilla de RandomX generalmente es el hash del bloque anterior o un valor similar
    RandomXHash calculateHash(const std::vector<uint8_t>& data, const std::vector<uint8_t>& seed);

private:
    randomx_cache *cache;
    randomx_vm *vm;
    bool initialized;

    // Inicializa RandomX con una semilla (que en un blockchain real, cambia con el tiempo)
    void initialize(const std::vector<uint8_t>& seed);
};

// Convierte un RandomXHash a una cadena hexadecimal
std::string toHexString(const RandomXHash& hash);

// Convierte una cadena hexadecimal a RandomXHash
RandomXHash fromHexString(const std::string& hexString);

} // namespace Radix

#endif // RANDOMX_UTIL_H