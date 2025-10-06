#ifndef PERSISTENCE_UTIL_H
#define PERSISTENCE_UTIL_H

#include <fstream>
#include <string>
#include <vector>
#include <cstdint>
#include <stdexcept>

namespace Radix {
namespace Persistence {

// Escribir tipos primitivos
// Utiliza reinterpret_cast para escribir el tipo directamente en el stream binario.
template <typename T>
void writePrimitive(std::fstream& fs, const T& data) {
    fs.write(reinterpret_cast<const char*>(&data), sizeof(T));
    if (!fs.good()) {
        throw std::runtime_error("Error escribiendo tipo primitivo en el archivo binario.");
    }
}

// Leer tipos primitivos
// Lee bytes directamente y los interpreta como el tipo T.
template <typename T>
T readPrimitive(std::fstream& fs) {
    T data;
    fs.read(reinterpret_cast<char*>(&data), sizeof(T));
    if (!fs.good() && !fs.eof()) {
        throw std::runtime_error("Error leyendo tipo primitivo desde el archivo binario.");
    }
    if (fs.eof() && fs.gcount() < sizeof(T)) {
        throw std::runtime_error("Fin de archivo prematuro al leer tipo primitivo.");
    }
    return data;
}

// Escribir std::string: Escribe la longitud (size_t) seguida de los bytes.
void writeString(std::fstream& fs, const std::string& str);
// Leer std::string: Lee la longitud (size_t) y luego los bytes.
std::string readString(std::fstream& fs);

// Escribir std::vector<uint8_t>: Escribe la longitud (size_t) seguida de los bytes.
void writeVector(std::fstream& fs, const std::vector<uint8_t>& vec);
// Leer std::vector<uint8_t>: Lee la longitud (size_t) y luego los bytes.
std::vector<uint8_t> readVector(std::fstream& fs);


} // namespace Persistence
} // namespace Radix

#endif // PERSISTENCE_UTIL_H