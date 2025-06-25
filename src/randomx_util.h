#ifndef RANDOM_X_UTIL_H
#define RANDOM_X_UTIL_H

#include <randomx.h>
#include <vector>
#include <string>
#include <array>
#include <cstdint> // Necesario para uint8_t

namespace Radix {

// Tipo para representar el hash de 32 bytes (RandomXHash)
using RandomXHash = std::array<uint8_t, 32>; // Cambiado a uint8_t para consistencia

// Tipo para representar una dirección Radix
using Address = std::string;

// Clase para encapsular el contexto de RandomX
class RandomXContext {
public:
    RandomXContext();
    ~RandomXContext();

    // Métodos para inicializar el caché y el dataset (ahora públicos y declarados)
    void initCache(const std::vector<uint8_t>& seed);
    void initDataset();

    // Métodos para calcular el hash (renombrados de calculateHash a hash)
    RandomXHash hash(const std::vector<uint8_t>& data) const;
    RandomXHash hash(const std::string& data) const; // Sobrecarga para strings

private:
    randomx_flags flags;
    randomx_vm* vm;
    randomx_cache* cache;
    randomx_dataset* dataset;
};

// Funciones de utilidad para convertir hashes y bytes a string hexadecimal
std::string toHexString(const RandomXHash& hash);
std::string toHexString(const std::vector<uint8_t>& bytes);

} // namespace Radix

#endif // RANDOM_X_UTIL_H
