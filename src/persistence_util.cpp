#include "persistence_util.h"
#include <cstring>
#include <iostream>

namespace Soverx {
namespace Persistence {

// Implementación de Escribir std::string
void writeString(std::ostream& fs, const std::string& str) {
    size_t len = str.length();
    writePrimitive(fs, len); 
    fs.write(str.data(), len); 
    if (!fs.good()) {
        throw std::runtime_error("Error escribiendo std::string en el stream binario.");
    }
}

// Implementación de Leer std::string
std::string readString(std::istream& fs) {
    size_t len = readPrimitive<size_t>(fs); 
    if (len == 0) return "";
    
    std::string str(len, '\0');
    fs.read(str.data(), len); 
    if (!fs.good() && !fs.eof()) {
        throw std::runtime_error("Error leyendo std::string desde el stream binario.");
    }
    if (fs.gcount() < len) {
        throw std::runtime_error("Fin de stream prematuro al leer std::string.");
    }
    return str;
}

// Implementación de Escribir std::vector<uint8_t>
void writeVector(std::ostream& fs, const std::vector<uint8_t>& vec) {
    size_t len = vec.size();
    writePrimitive(fs, len); 
    fs.write(reinterpret_cast<const char*>(vec.data()), len); 
    if (!fs.good()) {
        throw std::runtime_error("Error escribiendo std::vector<uint8_t> en el stream binario.");
    }
}

// Implementación de Leer std::vector<uint8_t>
std::vector<uint8_t> readVector(std::istream& fs) {
    size_t len = readPrimitive<size_t>(fs); 
    if (len == 0) return {};
    
    std::vector<uint8_t> vec(len);
    fs.read(reinterpret_cast<char*>(vec.data()), len); 
    if (!fs.good() && !fs.eof()) {
        throw std::runtime_error("Error leyendo std::vector<uint8_t> desde el stream binario.");
    }
    if (fs.gcount() < len) {
        throw std::runtime_error("Fin de stream prematuro al leer std::vector<uint8_t>.");
    }
    return vec;
}

} // namespace Persistence
} // namespace Soverx