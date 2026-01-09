// crypto.h
#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <vector>
#include <array>
#include <cstdint> // Para uint8_t

#include "randomx_util.h" // Para RandomXHash

// OpenSSL Headers para tipos necesarios
#include <openssl/ec.h>     // Para EC_KEY, EC_GROUP, EC_POINT
#include <openssl/ecdsa.h>  // Para ECDSA_SIG

namespace Soverx {

// Tipos personalizados para mayor claridad
using PrivateKey = std::array<uint8_t, 32>; // Clave privada de 32 bytes
using PublicKey = std::vector<uint8_t>;    // Clave pública (puede ser de 33 o 65 bytes)
using Signature = std::vector<uint8_t>;    // Firma (formato DER, longitud variable)

// --- Funciones de Utilidad Criptográficas (generales) ---
std::vector<uint8_t> hash160(const std::vector<uint8_t>& data);
std::string base58Encode(const std::vector<uint8_t>& data);
std::vector<uint8_t> base58Decode(const std::string& data);

// Wrapper para SHA256 (global de OpenSSL) en el namespace Soverx
RandomXHash SHA256(const std::string& data);
RandomXHash SHA256(const std::vector<uint8_t>& data);


class KeyPair {
public:
    // Constructor que genera un nuevo par de claves aleatorio
    KeyPair();
    // Constructor que usa una clave privada existente
    KeyPair(const PrivateKey& privKey);

    // Getters para las claves y la dirección
    const PrivateKey& getPrivateKey() const { return privateKey; }
    const PublicKey& getPublicKey() const { return publicKey; }
    const Address& getAddress() const { return address; }

    // Firma un hash de mensaje con la clave privada
    Signature sign(const RandomXHash& messageHash) const;
    // Verifica una firma con la clave pública
    static bool verify(const PublicKey& pubKey, const RandomXHash& messageHash, const Signature& signature);

    // Deriva una dirección a partir de una clave pública dada
    static Address deriveAddress(const PublicKey& pubKey);

private:
    PrivateKey privateKey;
    PublicKey publicKey;
    Address address;

    // Genera un nuevo par de claves EC
    void generateKeys();
    // Deriva la clave pública a partir de la clave privada
    void derivePublicKey();
    // Deriva la dirección a partir de la clave pública (internamente)
    void deriveAddressInternal();
};

} // namespace Soverx

#endif // CRYPTO_H
