// money_util.h
#ifndef MONEY_UTIL_H
#define MONEY_UTIL_H

#include <string>
#include <cstdint> // Para uint64_t

namespace Soverx {

// Factor de conversión (1 RDX = 100,000,000 rads)
const uint64_t RDX_DECIMAL_FACTOR = 100000000ULL; 

// Función auxiliar para convertir uint64_t (rads) a string con decimales (RDX)
std::string formatRadsToRDX(uint64_t rads);

} // namespace Soverx

#endif // MONEY_UTIL_H