#include "crypto.h"
#include "randomx_util.h" // Para toHexString
#include <iostream>
#include <stdexcept>
#include <string>
#include <cstring> // Para memcpy
#include <algorithm> // Para std::all_of

// OpenSSL Headers (APIs más antiguas y sus dependencias)
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h> // Para números aleatorios seguros
#include <openssl/ec.h>
#include <openssl/obj_mac.h> // Para NID_secp256k1
#include <openssl/sha.h>     // Para SHA256 directamente (API antigua)
#include <openssl/ripemd.h>  // Para RIPEMD160 directamente (API antigua)
#include <openssl/ecdsa.h>   // Para ECDSA_do_sign/verify (API antigua)
#include <openssl/err.h>     // Para manejo de errores de OpenSSL

// Se omiten headers específicos de OpenSSL 3.0 para EVP_PKEY_CTX, OSSL_PARAM, etc.,
// ya que el objetivo es usar la API deprecada.

namespace Radix {

// --------------------------------------------------------------------------------
// Funciones de Utilidad Criptográficas (fuera de la clase KeyPair)
// --------------------------------------------------------------------------------

// Calcula SHA256(RIPEMD160(data)) - conocido como Hash160
// Se utilizan las funciones directas SHA256 y RIPEMD160 de OpenSSL (APIs antiguas).
std::vector<uint8_t> hash160(const std::vector<uint8_t>& data) {
    unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
    ::SHA256(data.data(), data.size(), sha256_digest); // Uso explícito de :: para la función global de OpenSSL SHA256

    unsigned char ripemd160_digest[RIPEMD160_DIGEST_LENGTH];
    ::RIPEMD160(sha256_digest, SHA256_DIGEST_LENGTH, ripemd160_digest); // Uso explícito de :: para la función global de OpenSSL RIPEMD160

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
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        BN_free(bn); BN_free(base); BN_free(mod); BN_free(zero);
        throw std::runtime_error("Error al crear BN_CTX para Base58 encoding.");
    }

    while (BN_cmp(bn, zero) > 0) {
        if (!BN_div(bn, mod, bn, base, ctx)) {
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
    if (!ctx) {
        BN_free(bn); BN_free(base); BN_free(temp_char_val);
        throw std::runtime_error("Error al crear BN_CTX para Base58 decoding.");
    }

    for (char c : data) {
        size_t val = std::string(BASE58_ALPHABET).find(c);
        if (val == std::string::npos) {
            BN_CTX_free(ctx);
            BN_free(bn); BN_free(base); BN_free(temp_char_val);
            throw std::runtime_error("Invalid Base58 character: " + std::string(1, c));
        }
        BN_set_word(temp_char_val, val);
        if (!BN_mul(bn, bn, base, ctx) || !BN_add(bn, bn, temp_char_val)) {
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

// Implementación de los wrappers SHA256 usando la API antigua de OpenSSL.
Radix::RandomXHash SHA256(const std::string& data) {
    Radix::RandomXHash hash_result;
    ::SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash_result.data());
    return hash_result;
}

Radix::RandomXHash SHA256(const std::vector<uint8_t>& data) {
    Radix::RandomXHash hash_result;
    ::SHA256(data.data(), data.size(), hash_result.data());
    return hash_result;
}


// --------------------------------------------------------------------------------
// Implementación de la clase KeyPair
// --------------------------------------------------------------------------------

// Constructor que genera un nuevo par de claves aleatorio
KeyPair::KeyPair() {
    generateKeys();
    derivePublicKey();
    deriveAddressInternal();
}

// Constructor que usa una clave privada existente
KeyPair::KeyPair(const PrivateKey& privKey) : privateKey(privKey) {
    derivePublicKey();
    deriveAddressInternal();
}

// Genera un nuevo par de claves EC (usando API antigua EC_KEY).
void KeyPair::generateKeys() {
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1); // DEPRECATED in OpenSSL 3.0
    if (!ec_key) {
        throw std::runtime_error("Error creating EC_KEY curve: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    if (1 != EC_KEY_generate_key(ec_key)) { // DEPRECATED in OpenSSL 3.0
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error generating EC key: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    const BIGNUM* priv_bn = EC_KEY_get0_private_key(ec_key); // DEPRECATED in OpenSSL 3.0
    if (!priv_bn) {
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error getting private key BIGNUM.");
    }
    
    int len = BN_num_bytes(priv_bn);
    if (len > privateKey.size()) {
        EC_KEY_free(ec_key);
        throw std::runtime_error("Generated private key is larger than expected buffer size.");
    }
    std::fill(privateKey.begin(), privateKey.end(), 0); 
    BN_bn2bin(priv_bn, privateKey.data() + (privateKey.size() - len));

    EC_KEY_free(ec_key); // DEPRECATED in OpenSSL 3.0
}

// Deriva la clave pública a partir de la clave privada (usando API antigua EC_KEY).
void KeyPair::derivePublicKey() {
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1); // DEPRECATED in OpenSSL 3.0
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

    if (1 != EC_KEY_set_private_key(ec_key, priv_bn)) { // DEPRECATED in OpenSSL 3.0
        BN_free(priv_bn);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error setting private key for public key derivation: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        BN_free(priv_bn);
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
    
    if (1 != EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, ctx)) {
        BN_free(priv_bn);
        EC_POINT_free(pub_point);
        BN_CTX_free(ctx);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error multiplying EC_POINT for public key derivation: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }
    BN_free(priv_bn);

    if (1 != EC_KEY_set_public_key(ec_key, pub_point)) { // DEPRECATED in OpenSSL 3.0
        EC_POINT_free(pub_point);
        BN_CTX_free(ctx);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error setting public key in EC_KEY object: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }
    EC_POINT_free(pub_point);

    unsigned char *temp_pub_ptr_buffer = nullptr;

    size_t len = EC_KEY_key2buf(ec_key, POINT_CONVERSION_UNCOMPRESSED, &temp_pub_ptr_buffer, ctx); // DEPRECATED in OpenSSL 3.0

    if (len == 0) {
        EC_KEY_free(ec_key);
        BN_CTX_free(ctx);
        throw std::runtime_error("Error getting public key buffer length for derivation.");
    }

    publicKey.resize(len);
    memcpy(publicKey.data(), temp_pub_ptr_buffer, len);
    OPENSSL_free(temp_pub_ptr_buffer); // Liberar la memoria asignada por EC_KEY_key2buf

    EC_KEY_free(ec_key); // DEPRECATED in OpenSSL 3.0
    BN_CTX_free(ctx);
}


void KeyPair::deriveAddressInternal() {
    std::vector<uint8_t> pubKeyHash = hash160(publicKey);

    std::vector<uint8_t> address_bytes_with_version;
    address_bytes_with_version.push_back(0x00); 
    address_bytes_with_version.insert(address_bytes_with_version.end(), pubKeyHash.begin(), pubKeyHash.end());

    unsigned char checksum_hash1[SHA256_DIGEST_LENGTH];
    ::SHA256(address_bytes_with_version.data(), address_bytes_with_version.size(), checksum_hash1); // Uso explícito de ::SHA256
    unsigned char checksum_hash2[SHA256_DIGEST_LENGTH];
    ::SHA256(checksum_hash1, SHA256_DIGEST_LENGTH, checksum_hash2); // Uso explícito de ::SHA256

    address_bytes_with_version.insert(address_bytes_with_version.end(), checksum_hash2, checksum_hash2 + 4);

    address = "R" + base58Encode(address_bytes_with_version); 
}

// Firma un hash de mensaje con la clave privada (usando API antigua ECDSA).
Signature KeyPair::sign(const RandomXHash& messageHash) const {
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1); // DEPRECATED in OpenSSL 3.0
    if (!ec_key) {
        throw std::runtime_error("Error creating EC_KEY curve for signing: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    BIGNUM* priv_bn = BN_bin2bn(privateKey.data(), privateKey.size(), NULL);
    if (!priv_bn) {
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error converting private key to BIGNUM for signing.");
    }
    if (1 != EC_KEY_set_private_key(ec_key, priv_bn)) { // DEPRECATED in OpenSSL 3.0
        BN_free(priv_bn);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error setting private key for signing: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    // ECDSA_do_sign directamente para firmar (DEPRECATED in OpenSSL 3.0)
    ECDSA_SIG* signature_obj = ECDSA_do_sign(messageHash.data(), messageHash.size(), ec_key);
    if (!signature_obj) {
        BN_free(priv_bn);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error signing message: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    int der_len = i2d_ECDSA_SIG(signature_obj, NULL); // DEPRECATED in OpenSSL 3.0
    if (der_len <= 0) {
        ECDSA_SIG_free(signature_obj); // DEPRECATED in OpenSSL 3.0
        BN_free(priv_bn);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error getting DER signature length.");
    }

    Signature sig_vec(der_len);
    unsigned char* der_ptr = sig_vec.data();
    if (der_len != i2d_ECDSA_SIG(signature_obj, &der_ptr)) { // DEPRECATED in OpenSSL 3.0
        ECDSA_SIG_free(signature_obj); // DEPRECATED in OpenSSL 3.0
        BN_free(priv_bn);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error converting signature to DER format: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    ECDSA_SIG_free(signature_obj); // DEPRECATED in OpenSSL 3.0
    BN_free(priv_bn);
    EC_KEY_free(ec_key); // DEPRECATED in OpenSSL 3.0

    return sig_vec;
}

// Verifica una firma con la clave pública (usando API antigua ECDSA).
bool KeyPair::verify(const PublicKey& pubKey, const RandomXHash& messageHash, const Signature& signature) {
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1); // DEPRECATED in OpenSSL 3.0
    if (!ec_key) {
        std::cerr << "Error creating EC_KEY curve for verification: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    }

    const unsigned char* pub_ptr = pubKey.data();
    // o2i_ECPublicKey para deserializar el punto de la clave pública (DEPRECATED in OpenSSL 3.0)
    if (!o2i_ECPublicKey(&ec_key, &pub_ptr, pubKey.size())) { 
        std::cerr << "Error converting public key from bytes for verification: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EC_KEY_free(ec_key); // DEPRECATED in OpenSSL 3.0
        return false;
    }

    ECDSA_SIG* signature_obj = ECDSA_SIG_new(); // DEPRECATED in OpenSSL 3.0
    const unsigned char* sig_ptr = signature.data();
    if (!d2i_ECDSA_SIG(&signature_obj, &sig_ptr, signature.size())) { // DEPRECATED in OpenSSL 3.0
        std::cerr << "Error converting DER signature for verification: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        ECDSA_SIG_free(signature_obj); // DEPRECATED in OpenSSL 3.0
        EC_KEY_free(ec_key); // DEPRECATED in OpenSSL 3.0
        return false;
    }

    int result = ECDSA_do_verify(messageHash.data(), messageHash.size(), signature_obj, ec_key); // DEPRECATED in OpenSSL 3.0

    ECDSA_SIG_free(signature_obj); // DEPRECATED in OpenSSL 3.0
    EC_KEY_free(ec_key); // DEPRECATED in OpenSSL 3.0

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

    unsigned char checksum_hash1[SHA256_DIGEST_LENGTH];
    ::SHA256(address_bytes_with_version.data(), address_bytes_with_version.size(), checksum_hash1); // Uso explícito de ::SHA256
    unsigned char checksum_hash2[SHA256_DIGEST_LENGTH];
    ::SHA256(checksum_hash1, SHA256_DIGEST_LENGTH, checksum_hash2); // Uso explícito de ::SHA256

    address_bytes_with_version.insert(address_bytes_with_version.end(), checksum_hash2, checksum_hash2 + 4);

    return "R" + base58Encode(address_bytes_with_version); 
}

} // namespace Radix
