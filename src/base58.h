// base58.h
#ifndef BASE58_H
#define BASE58_H

#include <string>
#include <vector>

namespace Radix {
namespace Base58 {

// Codifica un vector de bytes a una cadena Base58
std::string encode(const std::vector<unsigned char>& data);

// Decodifica una cadena Base58 a un vector de bytes
std::vector<unsigned char> decode(const std::string& data);

} // namespace Base58
} // namespace Radix

#endif // BASE58_H