#include "crypto.h"
#include "randomx_util.h" // Para toHexString
#include <iostream>
#include <stdexcept>
#include <string>
#include <cstring> // Para memcpy
#include <algorithm> // Para std::all_of

// OpenSSL Headers
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h> // Para números aleatorios seguros
#include <openssl/ec.h>
#include <openssl/obj_mac.h> // Para NID_secp256k1
#include <openssl/sha.h>
#include <openssl/ripemd.h> // Para RIPEMD160
#include <openssl/ecdsa.h>
#include <openssl/err.h>    // Para manejo de errores de OpenSSL
#include <openssl/core_names.h> // Para OSSL_PKEY_PARAM_*
#include <openssl/param_build.h> // Para OSSL_PARAM_BLD_*
#include <openssl/provider.h> // Para OSSL_PROVIDER_load

namespace Radix {

// --------------------------------------------------------------------------------
// Funciones de Utilidad Criptográficas (fuera de la clase KeyPair)
// --------------------------------------------------------------------------------

// Calculates SHA256(RIPEMD160(data)) - known as Hash160
// Migrated to EVP_MD_CTX to eliminate RIPEMD160 warning.
std::vector<uint8_t> hash160(const std::vector<uint8_t>& data) {
    // Usa Radix::SHA256 para obtener el hash
    Radix::RandomXHash sha256_hash = Radix::SHA256(data); // Usa la función SHA256 definida a continuación

    // Usa EVP_MD_CTX para RIPEMD160
    unsigned char ripemd160_digest[RIPEMD160_DIGEST_LENGTH]; // RIPEMD160_DIGEST_LENGTH is 20 bytes
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        throw std::runtime_error("Error creating EVP_MD_CTX for RIPEMD160.");
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_ripemd160(), NULL)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Error initializing RIPEMD160 digest.");
    }
    if (1 != EVP_DigestUpdate(mdctx, sha256_hash.data(), sha256_hash.size())) { // Usa sha256_hash.data()
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Error updating RIPEMD160 digest.");
    }
    unsigned int len = 0;
    if (1 != EVP_DigestFinal_ex(mdctx, ripemd160_digest, &len)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Error finalizing RIPEMD160 digest.");
    }
    EVP_MD_CTX_free(mdctx);

    return std::vector<uint8_t>(ripemd160_digest, ripemd160_digest + RIPEMD160_DIGEST_LENGTH);
}

const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::string base58Encode(const std::vector<uint8_t>& data) {
    if (data.empty()) return "";

    BIGNUM* bn = BN_bin2bn(data.data(), data.size(), NULL);
    if (!bn) {
        throw std::runtime_error("Error converting bytes to BIGNUM for Base58 encoding.");
    }

    std::string encoded = "";
    BIGNUM* base = BN_new();
    BIGNUM* mod = BN_new();
    BIGNUM* zero = BN_new();
    BN_set_word(base, 58);
    BN_zero(zero);
    BN_CTX* ctx = BN_CTX_new(); // Context for BIGNUM operations
    if (!ctx) { // Add verification for ctx
        BN_free(bn); BN_free(base); BN_free(mod); BN_free(zero);
        throw std::runtime_error("Error creating BN_CTX for Base58 encoding.");
    }

    while (BN_cmp(bn, zero) > 0) {
        if (!BN_div(bn, mod, bn, base, ctx)) { // bn = bn / base, mod = bn % base
            BN_CTX_free(ctx);
            BN_free(bn); BN_free(base); BN_free(mod); BN_free(zero);
            throw std::runtime_error("Error during BIGNUM division for Base58 encoding.");
        }
        encoded = BASE58_ALPHABET[BN_get_word(mod)] + encoded;
    }

    int num_leading_zeros = 0;
    for (size_t i = 0; i < data.size(); ++i) {
        if (data[i] == 0x00) {
            num_leading_zeros++;
        } else {
            break;
        }
    }
    encoded = std::string(num_leading_zeros, '1') + encoded;

    BN_CTX_free(ctx);
    BN_free(bn);
    BN_free(base);
    BN_free(mod);
    BN_free(zero);
    return encoded;
}

std::vector<uint8_t> base58Decode(const std::string& data) {
    if (data.empty()) return {};

    BIGNUM* bn = BN_new();
    BIGNUM* base = BN_new();
    BIGNUM* temp_char_val = BN_new();
    BN_set_word(base, 58);
    BN_zero(bn);
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) { // Add verification for ctx
        BN_free(bn); BN_free(base); BN_free(temp_char_val);
        throw std::runtime_error("Error creating BN_CTX for Base58 decoding.");
    }

    for (char c : data) {
        size_t val = std::string(BASE58_ALPHABET).find(c);
        if (val == std::string::npos) {
            BN_CTX_free(ctx);
            BN_free(bn); BN_free(base); BN_free(temp_char_val);
            throw std::runtime_error("Invalid Base58 character: " + std::string(1, c));
        }
        BN_set_word(temp_char_val, val);
        if (!BN_mul(bn, bn, base, ctx) || !BN_add(bn, bn, temp_char_val)) { // Make sure to use ctx in BN_mul
            BN_CTX_free(ctx);
            BN_free(bn); BN_free(base); BN_free(temp_char_val);
            throw std::runtime_error("Error during BIGNUM multiplication/addition for Base58 decoding.");
        }
    }

    int num_leading_ones = 0;
    for (char c : data) {
        if (c == '1') {
            num_leading_ones++;
        } else {
            break;
        }
    }

    int num_bytes = BN_num_bytes(bn);
    std::vector<uint8_t> decoded_bytes(num_bytes);
    if (num_bytes > 0) {
        BN_bn2bin(bn, decoded_bytes.data());
    }

    std::vector<uint8_t> result(num_leading_ones, 0x00);
    result.insert(result.end(), decoded_bytes.begin(), decoded_bytes.end());

    BN_CTX_free(ctx);
    BN_free(bn);
    BN_free(base);
    BN_free(temp_char_val);
    return result;
}

// Implementación de los wrappers SHA256
Radix::RandomXHash SHA256(const std::string& data) {
    Radix::RandomXHash hash_result;
    // Usar la función SHA256 global de OpenSSL
    ::SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash_result.data());
    return hash_result;
}

Radix::RandomXHash SHA256(const std::vector<uint8_t>& data) {
    Radix::RandomXHash hash_result;
    // Usar la función SHA256 global de OpenSSL
    ::SHA256(data.data(), data.size(), hash_result.data());
    return hash_result;
}


// --------------------------------------------------------------------------------
// KeyPair Class Implementation
// --------------------------------------------------------------------------------

// Constructor that generates a new random key pair
KeyPair::KeyPair() {
    generateKeys();
    derivePublicKey();
    deriveAddressInternal();
}

// Constructor that uses an existing private key
KeyPair::KeyPair(const PrivateKey& privKey) : privateKey(privKey) {
    derivePublicKey();
    deriveAddressInternal();
}

// Migrated to EVP_PKEY for key generation, eliminating warnings.
void KeyPair::generateKeys() {
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec_key_from_pkey = NULL; // To extract the underlying EC_KEY temporarily
    BIGNUM *priv_bn_extracted = NULL;

    // 1. Create a context for EC key generation
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!pctx) {
        throw std::runtime_error("Error creating EVP_PKEY_CTX for EC key generation: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    // 2. Initialize key generation
    if (1 != EVP_PKEY_keygen_init(pctx)) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Error initializing EVP_PKEY_keygen: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    // 3. Set the curve NID (secp256k1)
    if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp256k1)) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Error setting EC curve NID: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    // 4. Generate the key
    if (1 != EVP_PKEY_keygen(pctx, &pkey)) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Error generating EC key via EVP_PKEY: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    // 5. Extract the private key (BIGNUM) from the EVP_PKEY.
    ec_key_from_pkey = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec_key_from_pkey) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Error getting EC_KEY from EVP_PKEY.");
    }
    priv_bn_extracted = (BIGNUM*)EC_KEY_get0_private_key(ec_key_from_pkey); // Not const, but just for copying
    if (!priv_bn_extracted) {
        EC_KEY_free(ec_key_from_pkey); // Free the temporary EC_KEY
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Error getting private key BIGNUM from EC_KEY.");
    }

    int len = BN_num_bytes(priv_bn_extracted);
    if (len > privateKey.size()) {
        EC_KEY_free(ec_key_from_pkey); // Free the temporary EC_KEY
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Generated private key is larger than expected buffer size.");
    }
    std::fill(privateKey.begin(), privateKey.end(), 0);
    BN_bn2bin(priv_bn_extracted, privateKey.data() + (privateKey.size() - len));

    // Clean up resources
    EC_KEY_free(ec_key_from_pkey); // Free the temporary copy of EC_KEY
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
}

// Migrated to EVP_PKEY for public key derivation, eliminating warnings.
void KeyPair::derivePublicKey() {
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key) {
        throw std::runtime_error("Error creating EC_KEY curve for public key derivation: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    BIGNUM* priv_bn = BN_new();
    if (!priv_bn) {
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error creating BIGNUM for private key.");
    }

    if (!BN_bin2bn(privateKey.data(), privateKey.size(), priv_bn)) {
        BN_free(priv_bn);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error converting private key to BIGNUM for public key derivation.");
    }

    if (1 != EC_KEY_set_private_key(ec_key, priv_bn)) {
        BN_free(priv_bn);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error setting private key for public key derivation: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        BN_free(priv_bn); // Liberar antes de lanzar la excepción
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error al crear BN_CTX.");
    }

    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    if (!group) {
        BN_free(priv_bn);
        BN_CTX_free(ctx);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error getting EC_GROUP for public key derivation.");
    }

    EC_POINT* pub_point = EC_POINT_new(group);
    if (!pub_point) {
        BN_free(priv_bn);
        BN_CTX_free(ctx);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error creating EC_POINT for public key derivation.");
    }
    
    // Calcula el punto público: pub_point = priv_bn * G (generador de la curva)
    if (1 != EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, ctx)) {
        BN_free(priv_bn);
        EC_POINT_free(pub_point);
        BN_CTX_free(ctx);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error multiplying EC_POINT for public key derivation: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }
    BN_free(priv_bn); // Liberar priv_bn después de usarlo en EC_POINT_mul

    if (1 != EC_KEY_set_public_key(ec_key, pub_point)) {
        EC_POINT_free(pub_point);
        BN_CTX_free(ctx);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error setting public key in EC_KEY object: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }
    EC_POINT_free(pub_point); // Liberar pub_point

    unsigned char *temp_pub_ptr_buffer = nullptr;

    // Obtener el tamaño
    size_t len = EC_KEY_key2buf(ec_key, POINT_CONVERSION_UNCOMPRESSED, &temp_pub_ptr_buffer, ctx);

    if (len == 0) {
        EC_KEY_free(ec_key);
        BN_CTX_free(ctx);
        throw std::runtime_error("Error getting public key buffer length for derivation.");
    }

    publicKey.resize(len);
    memcpy(publicKey.data(), temp_pub_ptr_buffer, len);
    OPENSSL_free(temp_pub_ptr_buffer); // Liberar la memoria asignada por EC_KEY_key2buf

    EC_KEY_free(ec_key);
    BN_CTX_free(ctx);
}


void KeyPair::deriveAddressInternal() {
    std::vector<uint8_t> pubKeyHash = hash160(publicKey);

    std::vector<uint8_t> address_bytes_with_version;
    address_bytes_with_version.push_back(0x00); 
    address_bytes_with_version.insert(address_bytes_with_version.end(), pubKeyHash.begin(), pubKeyHash.end());

    // Usa Radix::SHA256 para los checksums
    Radix::RandomXHash checksum_hash1 = Radix::SHA256(address_bytes_with_version);
    Radix::RandomXHash checksum_hash2 = Radix::SHA256(std::vector<uint8_t>(checksum_hash1.begin(), checksum_hash1.end()));

    address_bytes_with_version.insert(address_bytes_with_version.end(), checksum_hash2.begin(), checksum_hash2.begin() + 4);

    address = "R" + base58Encode(address_bytes_with_version); 
}

// Migrated to EVP_DigestSign* for signing, eliminating warnings.
Signature KeyPair::sign(const RandomXHash& messageHash) const {
    EVP_MD_CTX *mdctx = NULL; // Contexto de mensaje digerido
    EVP_PKEY_CTX *pctx_local = NULL; // Contexto de clave privada
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec_key_temp = NULL;
    BIGNUM *priv_bn = NULL;
    size_t siglen;
    Signature sig_vec;

    // 1. Convertir la clave privada de std::array a BIGNUM
    priv_bn = BN_bin2bn(privateKey.data(), privateKey.size(), NULL);
    if (!priv_bn) {
        throw std::runtime_error("Error converting private key to BIGNUM for signing.");
    }

    // 2. Crear un EC_KEY y establecer la clave privada
    ec_key_temp = EC_KEY_new_by_curve_name(NID_secp256k1); 
    if (!ec_key_temp) {
        BN_free(priv_bn);
        throw std::runtime_error("Error creating EC_KEY curve for signing.");
    }
    if (1 != EC_KEY_set_private_key(ec_key_temp, priv_bn)) { 
        BN_free(priv_bn);
        EC_KEY_free(ec_key_temp);
        throw std::runtime_error("Error setting private key for EC_KEY during signing.");
    }
    BN_free(priv_bn);

    // 3. Crear un EVP_PKEY y asignarle el EC_KEY
    pkey = EVP_PKEY_new();
    if (!pkey) {
        EC_KEY_free(ec_key_temp);
        throw std::runtime_error("Error creating EVP_PKEY for signing.");
    }
    if (1 != EVP_PKEY_assign_EC_KEY(pkey, ec_key_temp)) {
        EC_KEY_free(ec_key_temp);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Error assigning EC_KEY to EVP_PKEY for signing.");
    }

    // 4. Crear un contexto de mensaje digerido
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Error creating EVP_MD_CTX for signing: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    // 5. Inicializar la operación de firma con SHA256
    // EVP_DigestSignInit toma EVP_MD_CTX* como primer argumento y EVP_PKEY_CTX** como segundo.
    if (1 != EVP_DigestSignInit(mdctx, &pctx_local, EVP_sha256(), NULL, pkey)) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Error initializing EVP_DigestSign: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    // 6. Actualizar el contexto con los datos a firmar
    if (1 != EVP_DigestSignUpdate(mdctx, messageHash.data(), messageHash.size())) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Error updating digest for signing: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    // 7. Obtener el tamaño de la firma
    if (1 != EVP_DigestSignFinal(mdctx, NULL, &siglen)) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Error getting signature length: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }
    sig_vec.resize(siglen);

    // 8. Realizar la firma final
    if (1 != EVP_DigestSignFinal(mdctx, sig_vec.data(), &siglen)) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Error signing message with EVP_DigestSign: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }
    sig_vec.resize(siglen); // Ajustar el tamaño final si es necesario

    // Limpiar recursos
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey); // Liberará pkey y el ec_key_temp asociado

    return sig_vec;
}

// Migrated to EVP_DigestVerify* for verification, eliminating warnings.
bool KeyPair::verify(const PublicKey& pubKey, const RandomXHash& messageHash, const Signature& signature) {
    EVP_MD_CTX *mdctx = NULL; // Contexto de mensaje digerido
    EVP_PKEY_CTX *pctx_local = NULL; // Contexto de clave pública
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec_key_temp = NULL;

    // 1. Crear un EC_KEY a partir de la clave pública (si es formato RAW de punto EC)
    const EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) {
        std::cerr << "Error creating EC_GROUP for public key parsing." << std::endl;
        return false;
    }
    EC_POINT* pub_point = EC_POINT_new(group);
    if (!pub_point) {
        EC_GROUP_free(const_cast<EC_GROUP*>(group)); // Liberar si falla la creación del punto
        std::cerr << "Error creating EC_POINT for public key parsing." << std::endl;
        return false;
    }
    // EC_POINT_oct2point lee un punto EC desde un buffer de bytes.
    if (1 != EC_POINT_oct2point(group, pub_point, pubKey.data(), pubKey.size(), NULL)) {
        EC_POINT_free(pub_point);
        EC_GROUP_free(const_cast<EC_GROUP*>(group)); // Liberar si falla la conversión del punto
        std::cerr << "Error converting public key bytes to EC_POINT." << std::endl;
        return false;
    }

    ec_key_temp = EC_KEY_new(); // Crea un nuevo EC_KEY vacío
    if (!ec_key_temp) {
        EC_POINT_free(pub_point);
        EC_GROUP_free(const_cast<EC_GROUP*>(group));
        std::cerr << "Error creating EC_KEY for verification." << std::endl;
        return false;
    }
    EC_KEY_set_group(ec_key_temp, group); // Asigna el grupo
    if (1 != EC_KEY_set_public_key(ec_key_temp, pub_point)) { 
        EC_POINT_free(pub_point);
        // EC_GROUP_free(const_cast<EC_GROUP*>(group)); // Ya gestionado por ec_key_temp
        EC_KEY_free(ec_key_temp);
        std::cerr << "Error setting public key in EC_KEY for verification." << std::endl;
        return false;
    }
    EC_POINT_free(pub_point); // Punto ahora gestionado por ec_key_temp
    // EC_GROUP_free(const_cast<EC_GROUP*>(group));     // Grupo ahora gestionado por ec_key_temp

    // 2. Crear un EVP_PKEY y asignarle el EC_KEY
    pkey = EVP_PKEY_new();
    if (!pkey) {
        EC_KEY_free(ec_key_temp);
        std::cerr << "Error creating EVP_PKEY for verification." << std::endl;
        return false;
    }
    if (1 != EVP_PKEY_assign_EC_KEY(pkey, ec_key_temp)) {
        EC_KEY_free(ec_key_temp);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Error assigning EC_KEY to EVP_PKEY for verification.");
    }

    // 3. Crear un contexto de mensaje digerido
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        std::cerr << "Error creating EVP_MD_CTX for verification: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    }

    // 4. Inicializar la operación de verificación con SHA256
    if (1 != EVP_DigestVerifyInit(mdctx, &pctx_local, EVP_sha256(), NULL, pkey)) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Error initializing EVP_DigestVerify: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    // 5. Actualizar el contexto con los datos a verificar
    if (1 != EVP_DigestVerifyUpdate(mdctx, messageHash.data(), messageHash.size())) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Error updating digest for verification: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    // 6. Realizar la verificación
    int result = EVP_DigestVerifyFinal(mdctx, signature.data(), signature.size());

    // Limpiar recursos
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey); // Liberará pkey y el ec_key_temp asociado.

    if (result == 1) {
        return true; 
    } else if (result == 0) {
        std::cerr << "Warning: Signature verification failed (invalid signature)." << std::endl;
        return false; 
    } else {
        std::cerr << "Error during signature verification: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false; 
    }
}

Address KeyPair::deriveAddress(const PublicKey& pubKey) {
    std::vector<uint8_t> pubKeyHash = hash160(pubKey);

    std::vector<uint8_t> address_bytes_with_version;
    address_bytes_with_version.push_back(0x00); 
    address_bytes_with_version.insert(address_bytes_with_version.end(), pubKeyHash.begin(), pubKeyHash.end());

    // Usa Radix::SHA256 para los checksums
    Radix::RandomXHash checksum_hash1 = Radix::SHA256(address_bytes_with_version);
    Radix::RandomXHash checksum_hash2 = Radix::SHA256(std::vector<uint8_t>(checksum_hash1.begin(), checksum_hash1.end()));

    address_bytes_with_version.insert(address_bytes_with_version.end(), checksum_hash2.begin(), checksum_hash2.begin() + 4);

    return "R" + base58Encode(address_bytes_with_version); 
}

} // namespace Radix
