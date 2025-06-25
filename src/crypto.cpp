#include "crypto.h"
#include "randomx_util.h" // Para toHexString
#include <iostream>
#include <stdexcept>
#include <string>
#include <cstring> // Para memcpy
#include <algorithm> // Para std::all_of

// Cabeceras de OpenSSL
#include <openssl/evp.h>    // Para las nuevas APIs EVP (hashes, firmas)
#include <openssl/bn.h>     // Para BIGNUM
#include <openssl/rand.h>   // Para números aleatorios seguros (si es necesario)
#include <openssl/ec.h>     // Para EC_KEY, EC_GROUP, EC_POINT (usadas para carga/derivación)
#include <openssl/obj_mac.h>// Para NID_secp256k1 y OBJ_nid2sn
#include <openssl/sha.h>    // Para SHA256 (aunque EVP_sha256() es preferido)
#include <openssl/err.h>    // Para manejo de errores de OpenSSL
#include <openssl/ecdsa.h>  // Para ECDSA_do_sign, ECDSA_do_verify
#include <openssl/core_names.h> // Para OSSL_PKEY_PARAM_* (aunque minimizado su uso)
#include <openssl/param_build.h> // Para OSSL_PARAM_BLD_* (aunque minimizado su uso)
#include <openssl/provider.h> // Para OSSL_PROVIDER_load

namespace Radix {

// NOTA MUY IMPORTANTE: Para asegurar que el proveedor "default" de OpenSSL esté cargado
// y que los mensajes de error de OpenSSL sean legibles,
// se recomienda añadir las siguientes líneas al inicio de tu función main()
// o en la inicialización global de tu aplicación, antes de cualquier otra llamada a OpenSSL:
//
// #include <openssl/err.h> // Asegúrate de incluir esta cabecera si aún no lo está
// #include <openssl/provider.h> // Asegúrate de incluir esta cabecera si aún no lo está
//
// int main() {
//     ERR_load_crypto_strings(); // Carga las descripciones de los errores de OpenSSL
//     OSSL_PROVIDER* default_provider = OSSL_PROVIDER_load(NULL, "default"); // Carga el proveedor "default"
//     if (!default_provider) {
//         std::cerr << "ERROR: No se pudo cargar el proveedor 'default' de OpenSSL." << std::endl;
//         ERR_print_errors_fp(stderr);
//         return 1;
//     }
//     // ... el resto de tu código de inicialización y ejecución
//
//     // Al final de tu aplicación, para liberar recursos (opcional pero buena práctica):
//     // OSSL_PROVIDER_unload(default_provider);
//     // ERR_free_strings();
// }
// Esto es crucial para que OpenSSL 3.x encuentre las implementaciones de curvas como secp256k1
// y para obtener mensajes de error detallados cuando uses ERR_print_errors_fp.


// --------------------------------------------------------------------------------
// Funciones de Utilidad Criptográficas (fuera de la clase KeyPair)
// --------------------------------------------------------------------------------

// Calcula SHA256(RIPEMD160(data)) - conocido como Hash160
// Migrado a EVP_MD_CTX para eliminar la advertencia de RIPEMD160.
std::vector<uint8_t> hash160(const std::vector<uint8_t>& data) {
    unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), sha256_digest); // SHA256_DIGEST_LENGTH es 32 bytes

    // Usar EVP_MD_CTX para RIPEMD160
    unsigned char ripemd160_digest[RIPEMD160_DIGEST_LENGTH]; // RIPEMD160_DIGEST_LENGTH es 20 bytes
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        throw std::runtime_error("Error creating EVP_MD_CTX for RIPEMD160.");
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_ripemd160(), NULL)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Error initializing RIPEMD160 digest.");
    }
    if (1 != EVP_DigestUpdate(mdctx, sha256_digest, SHA256_DIGEST_LENGTH)) {
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
    BN_CTX* ctx = BN_CTX_new(); // Contexto para operaciones BIGNUM
    if (!ctx) { // Añadir verificación para ctx
        BN_free(bn); BN_free(base); BN_free(mod); BN_free(zero);
        throw std::runtime_error("Error al crear BN_CTX para Base58 encoding.");
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
    // CORRECCIÓN: Usar BN_CTX_new() para inicializar BN_CTX*
    BN_CTX* ctx = BN_CTX_new(); 
    if (!ctx) { // Añadir verificación para ctx
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
        if (!BN_mul(bn, bn, base, ctx) || !BN_add(bn, bn, temp_char_val)) { // Asegúrate de usar ctx en BN_mul
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

// Genera un nuevo par de claves EC (privada y pública).
// NOTA: Algunas de las funciones de EC_KEY utilizadas aquí pueden estar marcadas
// como 'deprecated' en OpenSSL 3.x. Sin embargo, se mantienen por su funcionalidad
// demostrada y para evitar errores de tiempo de ejecución persistentes con las
// nuevas APIs EVP_PKEY_fromdata/raw_key para secp256k1 en algunos entornos.
void KeyPair::generateKeys() {
    // Usamos EC_KEY_new_by_curve_name y EC_KEY_generate_key.
    // Aunque pueden generar advertencias, son robustas y evitan los problemas de 'reason(0)'.
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key) {
        throw std::runtime_error("Error creating EC_KEY curve: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    if (1 != EC_KEY_generate_key(ec_key)) {
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error generating EC key: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    const BIGNUM* priv_bn = EC_KEY_get0_private_key(ec_key);
    if (!priv_bn) {
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error getting private key BIGNUM.");
    }
    
    // Convertir BIGNUM a std::array<uint8_t, 32>
    int len = BN_num_bytes(priv_bn);
    if (len > privateKey.size()) {
        EC_KEY_free(ec_key);
        throw std::runtime_error("Generated private key is larger than expected buffer size.");
    }
    std::fill(privateKey.begin(), privateKey.end(), 0); // Rellenar con ceros para claves más cortas
    BN_bn2bin(priv_bn, privateKey.data() + (privateKey.size() - len)); // Copiar los bytes al final del array

    EC_KEY_free(ec_key); // Liberar el objeto EC_KEY
}

// Carga la clave privada raw y deriva la clave pública raw.
// NOTA: Similar a generateKeys, se usan funciones de EC_KEY que pueden estar
// marcadas como 'deprecated' por OpenSSL 3.x, pero que ofrecen estabilidad.
void KeyPair::derivePublicKey() {
    // Validar clave privada antes de proceder
    bool all_zero = std::all_of(privateKey.begin(), privateKey.end(), [](uint8_t b) { return b == 0; });
    if (all_zero) {
        throw std::runtime_error("Clave privada inválida: es todo ceros.");
    }

    BIGNUM* priv_bn = BN_new(); 
    if (!priv_bn) {
        throw std::runtime_error("Error creando BIGNUM para clave privada.");
    }

    if (!BN_bin2bn(privateKey.data(), privateKey.size(), priv_bn)) {
        BN_free(priv_bn);
        throw std::runtime_error("Error convirtiendo clave privada a BIGNUM para validación de rango.");
    }

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) {
        BN_free(priv_bn);
        throw std::runtime_error("Error obteniendo el grupo EC de secp256k1 para validación de rango.");
    }

    BIGNUM* order = BN_new();
    if (!order) {
        BN_free(priv_bn);
        EC_GROUP_free(group);
        throw std::runtime_error("Error creando BIGNUM para el orden de la curva.");
    }

    if (1 != EC_GROUP_get_order(group, order, NULL)) {
        BN_free(priv_bn);
        BN_free(order);
        EC_GROUP_free(group);
        throw std::runtime_error("Error obteniendo el orden de la curva secp256k1.");
    }

    if (BN_is_zero(priv_bn) || BN_cmp(priv_bn, order) >= 0) {
        BN_free(priv_bn);
        BN_free(order);
        EC_GROUP_free(group);
        throw std::runtime_error("Clave privada fuera de rango válido (0 < priv < order) para secp256k1.");
    }
    
    // DEBUG: Imprimir los bytes de la clave privada antes de pasarla a OpenSSL
    std::cout << "DEBUG (derivePublicKey): Private Key Bytes being loaded into EC_KEY: ";
    for (size_t i = 0; i < privateKey.size(); ++i) {
        std::cout << std::hex << (int)privateKey[i] << " ";
    }
    std::cout << std::dec << std::endl;

    // Liberar BIGNUM y orden después de la validación
    BN_free(priv_bn); 
    BN_free(order);
    EC_GROUP_free(group);

    // --- Carga y Derivación de Clave Pública usando EC_KEY ---
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key) {
        throw std::runtime_error("Error creating EC_KEY curve for public key derivation: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    // Convertir la clave privada a BIGNUM nuevamente para establecerla en EC_KEY
    BIGNUM* priv_bn_for_key = BN_bin2bn(privateKey.data(), privateKey.size(), NULL);
    if (!priv_bn_for_key) {
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error convirtiendo clave privada a BIGNUM para EC_KEY.");
    }
    
    // Establecer la clave privada. EC_KEY_set_private_key toma posesión del BIGNUM.
    if (1 != EC_KEY_set_private_key(ec_key, priv_bn_for_key)) {
        BN_free(priv_bn_for_key); // Si falla, liberar aquí
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error setting private key in EC_KEY for public key derivation: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }
    // No liberar priv_bn_for_key aquí, EC_KEY lo hará.

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        EC_KEY_free(ec_key); // Liberar antes de lanzar excepción
        throw std::runtime_error("Error al crear BN_CTX.");
    }

    // Obtener el grupo EC del EC_KEY. No se libera aquí, ec_key lo gestiona.
    const EC_GROUP* key_group = EC_KEY_get0_group(ec_key);
    if (!key_group) {
        BN_CTX_free(ctx);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error obteniendo EC_GROUP desde EC_KEY para derivación pública.");
    }

    EC_POINT* pub_point = EC_POINT_new(key_group);
    if (!pub_point) {
        BN_CTX_free(ctx);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error creando EC_POINT para derivación de clave pública.");
    }
    
    // Calcula el punto público: pub_point = priv_bn_for_key * G (generador de la curva)
    // Usamos el BIGNUM de la clave privada para calcular el punto público.
    if (1 != EC_POINT_mul(key_group, pub_point, EC_KEY_get0_private_key(ec_key), NULL, NULL, ctx)) {
        EC_POINT_free(pub_point);
        BN_CTX_free(ctx);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error multiplicando EC_POINT para derivación de clave pública: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    // Establecer el punto público en el EC_KEY. EC_KEY_set_public_key toma posesión del EC_POINT.
    if (1 != EC_KEY_set_public_key(ec_key, pub_point)) {
        EC_POINT_free(pub_point); // Si falla, liberar aquí
        BN_CTX_free(ctx);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error estableciendo clave pública en objeto EC_KEY: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }
    // No liberar pub_point aquí, EC_KEY lo hará.

    // Serializar la clave pública a formato RAW (uncompressed: 0x04 || X || Y)
    // Primero, obtenemos el tamaño necesario para el buffer
    size_t len_pub = i2o_ECPublicKey(ec_key, NULL);
    if (len_pub == 0) {
        BN_CTX_free(ctx);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error obteniendo longitud de clave pública para serialización.");
    }
    publicKey.resize(len_pub);
    unsigned char* pub_ptr_target = publicKey.data(); 
    if (len_pub != i2o_ECPublicKey(ec_key, &pub_ptr_target)) {
        BN_CTX_free(ctx);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error serializando clave pública: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }
    
    EC_KEY_free(ec_key); // Libera ec_key, group y pub_point asociados
    BN_CTX_free(ctx);
}


void KeyPair::deriveAddressInternal() {
    std::vector<uint8_t> pubKeyHash = hash160(publicKey);

    std::vector<uint8_t> address_bytes_with_version;
    address_bytes_with_version.push_back(0x00); 
    address_bytes_with_version.insert(address_bytes_with_version.end(), pubKeyHash.begin(), pubKeyHash.end());

    unsigned char checksum_hash1[SHA256_DIGEST_LENGTH];
    SHA256(address_bytes_with_version.data(), address_bytes_with_version.size(), checksum_hash1);
    unsigned char checksum_hash2[SHA256_DIGEST_LENGTH];
    SHA256(checksum_hash1, SHA256_DIGEST_LENGTH, checksum_hash2);

    address_bytes_with_version.insert(address_bytes_with_version.end(), checksum_hash2, checksum_hash2 + 4);

    address = "R" + base58Encode(address_bytes_with_version); 
}

// Firma un hash de mensaje con la clave privada.
// NOTA: Utiliza ECDSA_do_sign, que puede ser 'deprecated' en OpenSSL 3.x.
Signature KeyPair::sign(const RandomXHash& messageHash) const {
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key) {
        throw std::runtime_error("Error creating EC_KEY curve for signing: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    BIGNUM* priv_bn = BN_bin2bn(privateKey.data(), privateKey.size(), NULL);
    if (!priv_bn) {
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error converting private key to BIGNUM for signing.");
    }
    // Establecer la clave privada. EC_KEY_set_private_key toma posesión del BIGNUM.
    if (1 != EC_KEY_set_private_key(ec_key, priv_bn)) {
        BN_free(priv_bn); // Si falla, liberar aquí
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error setting private key for signing: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }
    // No liberar priv_bn aquí.

    // Establecer la clave pública en el ec_key.
    // o2i_ECPublicKey consume el puntero, por eso se pasa una copia mutable.
    const unsigned char* pub_ptr_temp = publicKey.data();
    if (!o2i_ECPublicKey(&ec_key, &pub_ptr_temp, publicKey.size())) {
        // En caso de error, ec_key_temp ya está liberado o no se asignó correctamente.
        // Si o2i_ECPublicKey falla, ec_key puede haber sido liberado internamente o no
        // pero la clave privada ya ha sido asignada. Es más seguro liberar todo.
        EC_KEY_free(ec_key); // Asegurar la liberación.
        throw std::runtime_error("Error converting public key to EC_KEY for signing: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    ECDSA_SIG* signature_obj = ECDSA_do_sign(messageHash.data(), messageHash.size(), ec_key);
    if (!signature_obj) {
        EC_KEY_free(ec_key); // Liberar ec_key en caso de error de firma.
        throw std::runtime_error("Error signing message: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    // Obtener el tamaño de la firma DER
    int der_len = i2d_ECDSA_SIG(signature_obj, NULL);
    if (der_len <= 0) {
        ECDSA_SIG_free(signature_obj);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error getting DER signature length.");
    }

    Signature sig_vec(der_len);
    unsigned char* der_ptr = sig_vec.data();
    // i2d_ECDSA_SIG incrementa der_ptr, por eso se usa una copia.
    if (der_len != i2d_ECDSA_SIG(signature_obj, &der_ptr)) {
        ECDSA_SIG_free(signature_obj);
        EC_KEY_free(ec_key);
        throw std::runtime_error("Error converting signature to DER format: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    ECDSA_SIG_free(signature_obj); // Liberar objeto de firma
    EC_KEY_free(ec_key); // Liberar objeto de clave

    return sig_vec;
}

// Verifica una firma con la clave pública.
// NOTA: Utiliza ECDSA_do_verify, que puede ser 'deprecated' en OpenSSL 3.x.
bool KeyPair::verify(const PublicKey& pubKey, const RandomXHash& messageHash, const Signature& signature) {
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key) {
        std::cerr << "Error creating EC_KEY curve for verification: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    }

    // Cargar la clave pública en el ec_key.
    // o2i_ECPublicKey consume el puntero, por eso se pasa una copia mutable.
    const unsigned char* pub_ptr = pubKey.data();
    if (!o2i_ECPublicKey(&ec_key, &pub_ptr, pubKey.size())) {
        std::cerr << "Error converting public key from bytes for verification: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EC_KEY_free(ec_key);
        return false;
    }

    ECDSA_SIG* signature_obj = ECDSA_SIG_new();
    const unsigned char* sig_ptr = signature.data();
    // d2i_ECDSA_SIG consume el puntero, por eso se pasa una copia mutable.
    if (!d2i_ECDSA_SIG(&signature_obj, &sig_ptr, signature.size())) {
        std::cerr << "Error converting DER signature for verification: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        ECDSA_SIG_free(signature_obj);
        EC_KEY_free(ec_key);
        return false;
    }

    int result = ECDSA_do_verify(messageHash.data(), messageHash.size(), signature_obj, ec_key);

    ECDSA_SIG_free(signature_obj); // Liberar objeto de firma
    EC_KEY_free(ec_key); // Liberar objeto de clave

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
    SHA256(address_bytes_with_version.data(), address_bytes_with_version.size(), checksum_hash1);
    unsigned char checksum_hash2[SHA256_DIGEST_LENGTH];
    SHA256(checksum_hash1, SHA256_DIGEST_LENGTH, checksum_hash2);

    address_bytes_with_version.insert(address_bytes_with_version.end(), checksum_hash2, checksum_hash2 + 4);

    return "R" + base58Encode(address_bytes_with_version); 
}

} // namespace Radix
