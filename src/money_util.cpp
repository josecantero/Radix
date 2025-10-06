// money_util.cpp
#include "money_util.h"
#include <sstream> 
#include <iomanip> 

namespace Radix {

// Implementación de la función auxiliar para convertir uint64_t (rads) a string con decimales (RDX)
std::string formatRadsToRDX(uint64_t rads) {
    if (rads == 0) {
        return "0.0";
    }
    
    uint64_t integerPart = rads / RDX_DECIMAL_FACTOR;
    uint64_t decimalPart = rads % RDX_DECIMAL_FACTOR;

    std::stringstream ss;
    ss << integerPart << ".";

    // Imprimir la parte decimal con 8 ceros a la izquierda para el formato de 8 decimales
    ss << std::setfill('0') << std::setw(8) << decimalPart;
    
    std::string result = ss.str();
    
    // Eliminar ceros al final de la parte decimal para mejorar la lectura
    size_t end = result.find_last_not_of('0');
    if (end != std::string::npos && result[end] != '.') {
        result.resize(end + 1);
    } else if (end != std::string::npos && result[end] == '.') {
        result.pop_back(); 
    }
    
    return result;
}

} // namespace Radix