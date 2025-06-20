#ifndef RANDOM_X_UTIL_H
#define RANDOM_X_UTIL_H

#include <randomx.h>
#include <vector>
#include <string>
#include <array>
#include <cstdint> // Para uint8_t

namespace Radix {

// Definición de RandomXHash como un array de 32 bytes
using RandomXHash = std::array<uint8_t, 32>;
using Address = std::string; // Definición de Address para direcciones de billetera

// Clase para gestionar el contexto RandomX
class RandomXContext {
public:
    RandomXContext();
    ~RandomXContext();

    // Calcula un hash RandomX de los datos proporcionados.
    // Esta versión ahora solo toma los datos a hashear.
    RandomXHash calculateHash(const std::vector<uint8_t>& data);

private:
    randomx_cache* cache;
    randomx_vm* vm;
};

// Función de utilidad para convertir un hash RandomX (std::array<uint8_t, 32>) a una string hexadecimal
std::string toHexString(const RandomXHash& hash);

} // namespace Radix

#endif // RANDOM_X_UTIL_H