#include "blockchain.h"
#include "block.h"
#include "transaction.h"
#include "randomx_util.h"
#include "crypto.h" // Incluir el header de criptografía
#include <iostream>
#include <vector>
#include <memory>
#include <chrono> // Para std::chrono::duration_cast
#include <string>
#include <stdexcept> // Para std::runtime_error, std::exception

// Incluir las cabeceras de OpenSSL para la gestión de errores y proveedores
#include <openssl/err.h>
#include <openssl/provider.h>


int main() {
    // ---- INICIALIZACIÓN CRÍTICA DE OPENSSL ----
    // Cargar las descripciones de los errores criptográficos para mensajes detallados.
    ERR_load_crypto_strings();
    // Cargar el proveedor "default". Es esencial para que OpenSSL 3.x
    // encuentre las implementaciones de algoritmos y curvas como secp256k1.
    OSSL_PROVIDER* default_provider = OSSL_PROVIDER_load(NULL, "default");
    if (!default_provider) {
        std::cerr << "ERROR: No se pudo cargar el proveedor 'default' de OpenSSL." << std::endl;
        ERR_print_errors_fp(stderr); // Imprime errores detallados si la carga falla
        // Aunque generalmente no es fatal, para este ejercicio, es crítico.
        // En una aplicación de producción, podrías manejar esto de forma más elegante.
        return 1; 
    }
    std::cout << "Proveedores OpenSSL cargados exitosamente." << std::endl;
    // ------------------------------------------

    std::cout << "Iniciando Radix Blockchain Core...\n" << std::endl;

    try {
        // Inicializar RandomX context (puede tardar un poco)
        Radix::RandomXContext rxContext;

        // Pasa rxContext al constructor de Blockchain
        Radix::Blockchain blockchain(rxContext); 

        std::cout << "\n--- Información del Bloque Genesis ---" << std::endl;
        // Pasa rxContext al toString del bloque
        std::cout << blockchain.getLastBlock().toString(rxContext) << std::endl;

        // --- Demostración de Criptografía (OpenSSL) ---
        std::cout << "\n--- Demostración de Criptografía (OpenSSL) ---" << std::endl;

        // 1. Generación de claves (Alice)
        Radix::KeyPair aliceKeys; 
        std::cout << "Generando par de claves para Alice:" << std::endl;
        // Convertir PrivateKey (std::array) a std::vector<uint8_t> para base58Encode si es necesario
        std::cout << "  Private Key (Base58): " << Radix::base58Encode(std::vector<uint8_t>(aliceKeys.getPrivateKey().begin(), aliceKeys.getPrivateKey().end())) << std::endl; 
        std::cout << "  Public Key (Hex):   " << Radix::toHexString(aliceKeys.getPublicKey()) << std::endl; 
        std::cout << "  Address:            " << aliceKeys.getAddress() << std::endl; 

        // 2. Generación de claves (Bob)
        Radix::KeyPair bobKeys; 
        std::cout << "\nGenerando par de claves para Bob:" << std::endl;
        std::cout << "  Private Key (Base58): " << Radix::base58Encode(std::vector<uint8_t>(bobKeys.getPrivateKey().begin(), bobKeys.getPrivateKey().end())) << std::endl; 
        std::cout << "  Public Key (Hex):   " << Radix::toHexString(bobKeys.getPublicKey()) << std::endl; 
        std::cout << "  Address:            " << bobKeys.getAddress() << std::endl; 

        // 3. Crear un mensaje (o su hash) para firmar
        std::string message = "¡Hola, mundo blockchain de Radix!";
        Radix::RandomXHash messageHash; 
        // TEMPORAL: Para que compile sin una función SHA256 de string a RandomXHash:
        // Idealmente, esto sería un hash SHA256 real del mensaje.
        for (size_t i = 0; i < messageHash.size(); ++i) {
            messageHash[i] = (uint8_t)(message[i % message.length()] + i);
        }
        // FIN TEMPORAL

        std::cout << "\nMensaje a firmar: \"" << message << "\"" << std::endl;
        std::cout << "Hash del mensaje (para firma): " << Radix::toHexString(messageHash) << std::endl;

        // 4. Firmar el mensaje con la clave privada de Alice
        Radix::Signature aliceSignature = aliceKeys.sign(messageHash); 
        std::cout << "Firma de Alice: " << Radix::toHexString(aliceSignature) << std::endl; 

        // 5. Verificar la firma con la clave pública de Alice
        bool isSignatureValid = Radix::KeyPair::verify(aliceKeys.getPublicKey(), messageHash, aliceSignature); 
        std::cout << "VERIFICACION DE FIRMA: " << (isSignatureValid ? "Exitosa! La firma es valida." : "Fallida! La firma NO es valida.") << std::endl;

        // Prueba de verificación con clave pública incorrecta (de Bob)
        std::cout << "\nIntentando verificar la firma de Alice con la clave publica de Bob..." << std::endl;
        bool isInvalidSignatureValid = Radix::KeyPair::verify(bobKeys.getPublicKey(), messageHash, aliceSignature); 
        std::cout << "VERIFICACION DE FIRMA (con clave de Bob): " << (isInvalidSignatureValid ? "Exitosa! (ERROR, no deberia ser valida)" : "Fallida! (Correcto)" ) << std::endl;

        // --- Añadir algunos bloques de ejemplo ---
        std::vector<std::string> pendingTransactions; 
        pendingTransactions.push_back("Tx1: Alice envia 5 RDX a Bob");
        pendingTransactions.push_back("Tx2: Bob envia 2 RDX a Charlie");

        // Minar y añadir el primer bloque
        auto block1 = blockchain.mineNewBlock(rxContext, pendingTransactions);
        if (blockchain.addBlock(std::move(block1), rxContext, pendingTransactions)) {
            std::cout << "\n--- Información del Bloque #" << blockchain.getChainSize() - 1 << " ---" << std::endl; 
            std::cout << blockchain.getLastBlock().toString(rxContext) << std::endl;
        } else {
            std::cerr << "Fallo al añadir el Bloque #1." << std::endl;
        }

        pendingTransactions.clear(); 
        pendingTransactions.push_back("Tx3: Charlie envia 1 RDX a Alice");

        // Minar y añadir el segundo bloque
        auto block2 = blockchain.mineNewBlock(rxContext, pendingTransactions);
        if (blockchain.addBlock(std::move(block2), rxContext, pendingTransactions)) {
            std::cout << "\n--- Información del Bloque #" << blockchain.getChainSize() - 1 << " ---" << std::endl; 
            std::cout << blockchain.getLastBlock().toString(rxContext) << std::endl;
        } else {
            std::cerr << "Fallo al añadir el Bloque #2." << std::endl;
        }

    } catch (const std::runtime_error& e) {
        std::cerr << "terminate called after throwing an instance of 'std::runtime_error'" << std::endl;
        std::cerr << "  what():  " << e.what() << std::endl;
        ERR_print_errors_fp(stderr); // Imprimir errores detallados de OpenSSL si están disponibles
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Se capturó una excepción inesperada: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "\n¡Radix Blockchain Core finalizado!" << std::endl;

    // ---- LIBERACIÓN DE RECURSOS DE OPENSSL (opcional pero buena práctica) ----
    // Si tu aplicación termina aquí, puedes liberar estos recursos.
    // Si es un servicio de larga duración, es posible que no quieras liberarlos hasta el cierre.
    OSSL_PROVIDER_unload(default_provider); // CORREGIDO: Usar la variable default_provider
    ERR_free_strings();
    // --------------------------------------------------------------------------

    return 0;
}
