#include "blockchain.h"
#include "block.h"
#include "transaction.h"
#include "randomx_util.h"
#include "crypto.h" 
#include <iostream>
#include <vector>
#include <memory>
#include <chrono> // Para std::chrono::duration_cast
#include <string>
#include <stdexcept> // Para std::runtime_error, std::exception

// cabeceras de OpenSSL para la gestión de errores y proveedores
#include <openssl/err.h>
#include <openssl/provider.h>


int main() {
    // ---- INICIALIZACIÓN CRÍTICA DE OPENSSL ----
    std::cout << "Iniciando configuracion de OpenSSL..." << std::endl << std::flush;
    ERR_load_crypto_strings(); // Cargar las descripciones de los errores criptográficos
    
    OSSL_PROVIDER* default_provider = OSSL_PROVIDER_load(NULL, "default");
    if (!default_provider) {
        std::cerr << "ERROR: No se pudo cargar el proveedor 'default' de OpenSSL." << std::endl;
        ERR_print_errors_fp(stderr); // Imprime errores detallados
        return 1; 
    }
    std::cout << "Proveedores OpenSSL cargados exitosamente." << std::endl << std::flush;
    // ------------------------------------------

    std::cout << "\nIniciando Radix Blockchain Core...\n" << std::endl << std::flush;

    try {
        std::cout << "Creando contexto de RandomX (esto puede tardar unos segundos)..." << std::endl << std::flush;
        Radix::RandomXContext rxContext;
        // initCache e initDataset son llamadas dentro del constructor de RandomXContext.
        
        std::cout << "Contexto de RandomX listo." << std::endl << std::flush;

        // Ahora el constructor de Blockchain toma la dificultad y el contexto RandomX
        // Aumentar la dificultad para que la minería sea más notoria
        unsigned int blockchain_difficulty = 10; // Ajustado de 4 a 20 para ver el proceso de minería
        std::cout << "\nInicializando Blockchain con dificultad: " << blockchain_difficulty << std::endl << std::flush;
        Radix::Blockchain blockchain(blockchain_difficulty, rxContext); 
        std::cout << "Blockchain inicializada y Bloque Genesis creado." << std::endl << std::flush;

        std::cout << "\n--- Informacion del Bloque Genesis ---" << std::endl << std::flush;
        std::cout << blockchain.getLatestBlock().toString() << std::endl << std::flush;

        // --- Demostración de Criptografía (OpenSSL) ---
        std::cout << "\n--- Demostracion de Criptografia (OpenSSL) ---" << std::endl << std::flush;

        // Generar claves para Alice
        std::cout << "\nGenerando par de claves para Alice..." << std::endl << std::flush;
        Radix::KeyPair aliceKeys;
        std::cout << "  Direccion de Alice: " << aliceKeys.getAddress() << std::endl << std::flush;
        std::cout << "  Clave Publica de Alice (Hex): " << Radix::toHexString(aliceKeys.getPublicKey()) << std::endl << std::flush;

        // Generar claves para Bob
        std::cout << "\nGenerando par de claves para Bob..." << std::endl << std::flush;
        Radix::KeyPair bobKeys;
        std::cout << "  Direccion de Bob: " << bobKeys.getAddress() << std::endl << std::flush;
        std::cout << "  Clave Publica de Bob (Hex): " << Radix::toHexString(bobKeys.getPublicKey()) << std::endl << std::flush;

        // Crear un mensaje de prueba para firma
        std::string test_message = "Este es un mensaje de prueba para la firma digital.";
        // Calcula el hash del mensaje usando la función SHA256 de Radix
        Radix::RandomXHash messageHash = Radix::SHA256(test_message);

        std::cout << "\nMensaje original para firmar: \"" << test_message << "\"" << std::endl << std::flush;
        std::cout << "Hash del mensaje (para firma): " << Radix::toHexString(messageHash) << std::endl << std::flush;

        // Alice firma el mensaje
        std::cout << "\nAlice firmando el mensaje..." << std::endl << std::flush;
        Radix::Signature aliceSignature = aliceKeys.sign(messageHash); 
        std::cout << "  Firma generada por Alice (Hex): " << Radix::toHexString(aliceSignature) << std::endl << std::flush; 

        // Verificar la firma de Alice con su clave pública
        std::cout << "\nVerificando la firma de Alice con la clave publica de Alice..." << std::endl << std::flush;
        bool isSignatureValid = Radix::KeyPair::verify(aliceKeys.getPublicKey(), messageHash, aliceSignature); 
        std::cout << "  Resultado de la verificacion: " << (isSignatureValid ? "EXITOSA! La firma es valida." : "FALLIDA! La firma NO es valida.") << std::endl << std::flush;

        // Intentar verificar la firma de Alice con la clave pública de Bob (debería fallar)
        std::cout << "\nIntentando verificar la firma de Alice con la clave publica de Bob (esperado: FALLO)..." << std::endl << std::flush;
        bool isInvalidSignatureValid = Radix::KeyPair::verify(bobKeys.getPublicKey(), messageHash, aliceSignature); 
        std::cout << "  Resultado de la verificacion: " << (isInvalidSignatureValid ? "ERROR! La firma se valido (deberia fallar)." : "FALLO! (Correcto)" ) << std::endl << std::flush;

        // --- Demostración de Transacciones y Minería ---
        std::cout << "\n--- Demostracion de Transacciones y Mineria ---" << std::endl << std::flush;

        // Transacción 1: Alice envía 5 RDX a Bob
        std::cout << "\nCreando Transaccion 1: Alice envia 5 RDX a Bob." << std::endl << std::flush;
        Radix::Transaction tx1(false); // No es una transacción de coinbase
        tx1.inputs.push_back({"prevTxId_simulado_alice", 0, Radix::Signature(), aliceKeys.getPublicKey()}); // Input simulado
        tx1.outputs.push_back({5, bobKeys.getAddress()}); // Output a Bob
        tx1.updateId(); // Calcular el ID de la transacción
        std::cout << "  ID de Transaccion 1 (pre-firma): " << tx1.id << std::endl << std::flush;
        tx1.sign(aliceKeys); // Alice firma la transacción
        std::cout << "  Transaccion 1 firmada por Alice. ID: " << tx1.id << std::endl << std::flush;
        blockchain.addTransaction(tx1);
        std::cout << "  Transaccion 1 anadida a la piscina de transacciones pendientes." << std::endl << std::flush;
        
        // Minar el primer bloque con la transacción de Alice
        std::cout << "\nIniciando mineria del primer bloque. Minero: " << aliceKeys.getAddress() << std::endl << std::flush;
        // minePendingTransactions() ya no necesita rxContext como argumento
        blockchain.minePendingTransactions(aliceKeys.getAddress()); 
        std::cout << "Primer bloque minado y anadido a la cadena." << std::endl << std::flush;
        std::cout << "\n--- Informacion del Bloque #" << blockchain.getChainSize() - 1 << " ---" << std::endl << std::flush; 
        // toString() ya no necesita rxContext como argumento
        std::cout << blockchain.getLatestBlock().toString() << std::endl << std::flush;


        // Transacción 2: Bob envía 2 RDX a Alice
        std::cout << "\nCreando Transaccion 2: Bob envia 2 RDX a Alice." << std::endl << std::flush;
        Radix::Transaction tx2(false); // No es una transacción de coinbase
        tx2.inputs.push_back({"prevTxId_simulado_bob", 0, Radix::Signature(), bobKeys.getPublicKey()}); // Input simulado
        tx2.outputs.push_back({2, aliceKeys.getAddress()}); // Output a Alice
        tx2.updateId(); // Calcular el ID de la transacción
        std::cout << "  ID de Transaccion 2 (pre-firma): " << tx2.id << std::endl << std::flush;
        tx2.sign(bobKeys); // Bob firma la transacción
        std::cout << "  Transaccion 2 firmada por Bob. ID: " << tx2.id << std::endl << std::flush;
        blockchain.addTransaction(tx2);
        std::cout << "  Transaccion 2 anadida a la piscina de transacciones pendientes." << std::endl << std::flush;

        // Minar el segundo bloque con la transacción de Bob
        std::cout << "\nIniciando mineria del segundo bloque. Minero: " << bobKeys.getAddress() << std::endl << std::flush;
        // minePendingTransactions() ya no necesita rxContext como argumento
        blockchain.minePendingTransactions(bobKeys.getAddress());
        std::cout << "Segundo bloque minado y anadido a la cadena." << std::endl << std::flush;
        std::cout << "\n--- Informacion del Bloque #" << blockchain.getChainSize() - 1 << " ---" << std::endl << std::flush; 
        // toString() ya no necesita rxContext como argumento
        std::cout << blockchain.getLatestBlock().toString() << std::endl << std::flush;

        std::cout << "\n--- Estado Final de la Blockchain ---" << std::endl << std::flush;
        // printChain() ya no necesita rxContext como argumento
        blockchain.printChain();

        std::cout << "\nValidando la integridad de toda la Blockchain..." << std::endl << std::flush;
        // isChainValid() ya no necesita rxContext como argumento
        if (blockchain.isChainValid()) {
            std::cout << "La Blockchain es VALIDA! Todos los bloques y hashes son correctos." << std::endl << std::flush;
        } else {
            std::cout << "La Blockchain es INVALIDA! Se detectaron inconsistencias." << std::endl << std::flush;
        }

        // Mostrar balances
        std::cout << "\n--- Balances Finales ---" << std::endl << std::flush;
        std::cout << "Balance de Alice: " << blockchain.getBalanceOfAddress(aliceKeys.getAddress()) << " RDX" << std::endl << std::flush;
        std::cout << "Balance de Bob: " << blockchain.getBalanceOfAddress(bobKeys.getAddress()) << " RDX" << std::endl << std::flush;

    } catch (const std::runtime_error& e) {
        std::cerr << "Error critico en la aplicacion: " << e.what() << std::endl << std::flush;
        ERR_print_errors_fp(stderr); // Imprimir errores detallados de OpenSSL si están disponibles
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Se capturo una excepcion inesperada: " << e.what() << std::endl << std::flush;
        return 1;
    }

    std::cout << "\n¡Radix Blockchain Core finalizado!" << std::endl << std::flush;

    // ---- LIBERACIÓN DE RECURSOS DE OPENSSL ----
    OSSL_PROVIDER_unload(default_provider); 
    ERR_free_strings();
    // ------------------------------------------

    return 0;
}
