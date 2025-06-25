#ifndef CRYPTO_H
#define CRYPTO_H

#include <vector>
#include <string>
#include <array>
#include "randomx_util.h" // Para Radix::RandomXHash y Radix::Address
#include <openssl/ec.h>     // Para EC_KEY
#include <openssl/obj_mac.h> // Para NID_secp256k1
#include <openssl/sha.h>    // Para SHA256
#include <openssl/ripemd.h> // Para RIPEMD160

namespace Radix {

// Tipo para representar una clave privada (32 bytes)
using PrivateKey = std::array<uint8_t, 32>;
// Tipo para representar una clave pública (64 bytes descomprimida, o más si incluye punto 04)
using PublicKey = std::vector<uint8_t>;
// Tipo para la firma (DER encoding)
using Signature = std::vector<uint8_t>;

// Clase para la gestión de claves y firmas
class KeyPair {
public:
    KeyPair(); // Genera un nuevo par de claves aleatorio
    KeyPair(const PrivateKey& privKey); // Crea un par de claves a partir de una privada existente

    // Obtiene la clave privada
    const PrivateKey& getPrivateKey() const { return privateKey; }
    // Obtiene la clave pública (comprimida o sin comprimir, lo definiremos en la implementación)
    const PublicKey& getPublicKey() const { return publicKey; }
    // Obtiene la dirección derivada de la clave pública
    Address getAddress() const { return address; }

    // Firma un mensaje (hash) usando la clave privada
    Signature sign(const RandomXHash& messageHash) const;

    // Verifica una firma usando la clave pública
    static bool verify(const PublicKey& pubKey, const RandomXHash& messageHash, const Signature& signature);

    // Deriva una dirección Radix a partir de una clave pública
    static Address deriveAddress(const PublicKey& pubKey);

private:
    PrivateKey privateKey;
    PublicKey publicKey;
    Address address;

    // Funciones internas para generación/derivación
    void generateKeys();
    void derivePublicKey();
    void deriveAddressInternal();
};

// Funciones de utilidad criptográficas
std::vector<uint8_t> hash160(const std::vector<uint8_t>& data); // SHA256 + RIPEMD160
std::string base58Encode(const std::vector<uint8_t>& data);
std::vector<uint8_t> base58Decode(const std::string& data); // Implementación básica, sin checksum

} // namespace Radix

#endif // CRYPTO_H