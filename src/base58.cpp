// base58.cpp
#include "base58.h"
#include <algorithm> // For std::reverse
#include <stdexcept> // For std::runtime_error
#include <vector>

namespace Soverx {
namespace Base58 {

// El alfabeto Base58 (Bitcoin usa este)
const char* ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const int BASE = 58;

// Función auxiliar para realizar la división y obtener el resto
std::vector<unsigned char> divmod(std::vector<unsigned char>& number, int divisor, int& remainder) {
    remainder = 0;
    std::vector<unsigned char> result;
    for (unsigned char byte : number) {
        int temp = remainder * 256 + byte;
        result.push_back(static_cast<unsigned char>(temp / divisor));
        remainder = temp % divisor;
    }

    // Eliminar ceros iniciales
    auto it = result.begin();
    while (it != result.end() && *it == 0) {
        ++it;
    }
    result.erase(result.begin(), it);
    return result;
}

std::string encode(const std::vector<unsigned char>& data) {
    if (data.empty()) {
        return "";
    }

    std::vector<unsigned char> num = data;
    std::string encoded_string;

    // Contar los ceros iniciales
    int leading_zeros = 0;
    for (unsigned char byte : num) {
        if (byte == 0) {
            leading_zeros++;
        } else {
            break;
        }
    }

    while (!num.empty() && !(num.size() == 1 && num[0] == 0)) {
        int remainder;
        num = divmod(num, BASE, remainder);
        encoded_string += ALPHABET[remainder];
    }

    // Añadir los '1' (que representan 0 en Base58) por cada cero inicial
    for (int i = 0; i < leading_zeros; ++i) {
        encoded_string += ALPHABET[0]; // ALPHABET[0] es '1'
    }

    std::reverse(encoded_string.begin(), encoded_string.end());
    return encoded_string;
}

std::vector<unsigned char> decode(const std::string& data) {
    if (data.empty()) {
        return {};
    }

    // Inicializar el número decodificado a 0
    std::vector<unsigned char> decoded_num(1, 0);

    for (char char_code : data) {
        size_t val = std::string(ALPHABET).find(char_code);
        if (val == std::string::npos) {
            throw std::runtime_error("Caracter Base58 invalido: " + std::string(1, char_code));
        }

        // decoded_num = decoded_num * BASE + val
        int carry = val;
        for (size_t i = 0; i < decoded_num.size(); ++i) {
            int digit = decoded_num[i] * BASE + carry;
            decoded_num[i] = static_cast<unsigned char>(digit % 256);
            carry = digit / 256;
        }
        while (carry > 0) {
            decoded_num.push_back(static_cast<unsigned char>(carry % 256));
            carry /= 256;
        }
    }

    // Contar los '1's iniciales en la cadena Base58 (representan ceros iniciales en bytes)
    int leading_ones = 0;
    for (char char_code : data) {
        if (char_code == ALPHABET[0]) {
            leading_ones++;
        } else {
            break;
        }
    }

    // Añadir ceros iniciales al resultado decodificado
    std::vector<unsigned char> result;
    for (int i = 0; i < leading_ones; ++i) {
        result.push_back(0);
    }

    // Revertir el número y eliminar ceros iniciales (que pueden haber sido introducidos por el algoritmo)
    std::reverse(decoded_num.begin(), decoded_num.end());
    auto it = decoded_num.begin();
    while (it != decoded_num.end() && *it == 0) {
        ++it;
    }
    result.insert(result.end(), it, decoded_num.end());

    return result;
}

} // namespace Base58
} // namespace Soverx