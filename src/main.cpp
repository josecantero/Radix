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
        return 1; 
    }
    std::cout << "Proveedores OpenSSL cargados exitosamente." << std::endl;
    // ------------------------------------------

    std::cout << "Iniciando Radix Blockchain Core...\n" << std::endl;

    try {
        // Inicializar RandomX context (puede tardar un poco)
        Radix::RandomXContext rxContext;
        // Inicializar caché y dataset de RandomX
        rxContext.initCache({}); // Seed vacío por simplicidad
        rxContext.initDataset();

        // Pasa rxContext al constructor de Blockchain
        // CORRECCIÓN: Añadir el argumento de dificultad (ej. 10)
        Radix::Blockchain blockchain(10, rxContext); 

        std::cout << "\n--- Información del Bloque Genesis ---" << std::endl;
        // CORRECCIÓN: Cambiar getLastBlock() a getLatestBlock()
        std::cout << blockchain.getLatestBlock().toString() << std::endl;

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
        std::cout << "\nGenerando par de claves para Bob..." << std::endl;
        std::cout << "  Private Key (Base58): " << Radix::base58Encode(std::vector<uint8_t>(bobKeys.getPrivateKey().begin(), bobKeys.getPrivateKey().end())) << std::endl; 
        std::cout << "  Public Key (Hex):   " << Radix::toHexString(bobKeys.getPublicKey()) << std::endl; 
        std::cout << "  Address:            " << bobKeys.getAddress() << std::endl; 

        // 3. Crear un mensaje (o su hash) para firmar
        std::string message = "Este es un mensaje de prueba para la firma digital.";
        // CORRECCIÓN: Usar SHA256 real para el mensaje
        Radix::RandomXHash messageHash = Radix::SHA256(message); 

        std::cout << "\nMensaje original para firmar: \"" << message << "\"" << std::endl;
        std::cout << "Hash del mensaje (para firma): " << Radix::toHexString(messageHash) << std::endl;

        // 4. Firmar el mensaje con la clave privada de Alice
        Radix::Signature aliceSignature = aliceKeys.sign(messageHash); 
        std::cout << "Firma de Alice: " << Radix::toHexString(aliceSignature) << std::endl; 

        // 5. Verificar la firma con la clave pública de Alice
        bool isSignatureValid = Radix::KeyPair::verify(aliceKeys.getPublicKey(), messageHash, aliceSignature); 
        std::cout << "VERIFICACION DE FIRMA: " << (isSignatureValid ? "Exitosa! La firma es valida." : "Fallida! La firma NO es valida.") << std::endl;

        // Prueba de verificación con clave pública incorrecta (de Bob)
        std::cout << "\nIntentando verificar la firma de Alice con la clave publica de Bob (esperado: FALLO)..." << std::endl;
        bool isInvalidSignatureValid = Radix::KeyPair::verify(bobKeys.getPublicKey(), messageHash, aliceSignature); 
        std::cout << "VERIFICACION DE FIRMA (con clave de Bob): " << (isInvalidSignatureValid ? "Exitosa! (ERROR, no deberia ser valida)" : "Fallida! (Correcto)" ) << std::endl;

        // --- Demostración de Transacciones y Minería (con UTXO) ---
        std::cout << "\n--- Demostracion de Transacciones y Mineria (con UTXO) ---" << std::endl;

        // Minar un bloque inicial para Alice para darle fondos (recompensa de minería)
        std::cout << "\nMinando un bloque inicial para Alice para darle fondos..." << std::endl;
        blockchain.minePendingTransactions(aliceKeys.getAddress()); 
        std::cout << "Bloque inicial minado para Alice. Balance de Alice: " << blockchain.getBalanceOfAddress(aliceKeys.getAddress()) << " RDX" << std::endl;
        std::cout << "\n--- Informacion del Bloque #" << blockchain.getChainSize() - 1 << " ---" << std::endl; 
        std::cout << blockchain.getLatestBlock().toString() << std::endl;


        // Transacción 1: Alice envía 5 RDX a Bob.
        std::cout << "\nCreando Transaccion 1: Alice envia 5 RDX a Bob." << std::endl;
        
        // Obtener la UTXO de Alice de la coinbase del bloque anterior
        const Radix::Block& lastBlock = blockchain.getLatestBlock();
        if (lastBlock.transactions.empty() || !lastBlock.transactions[0].isCoinbase) {
             throw std::runtime_error("El ultimo bloque no contiene una transaccion coinbase esperada para Alice.");
        }
        // Asumiendo que la coinbase es la primera transacción y su única salida es el índice 0
        std::string aliceCoinbaseTxId = lastBlock.transactions[0].id; // El ID de la transacción coinbase
        double aliceCoinbaseAmount = lastBlock.transactions[0].outputs[0].amount; // El monto de la coinbase

        std::vector<Radix::TransactionInput> tx1_inputs;
        // Referencia a la UTXO de la coinbase de Alice (ID de la coinbase, índice 0)
        tx1_inputs.push_back({aliceCoinbaseTxId, 0, Radix::Signature(), aliceKeys.getPublicKey()}); 

        std::vector<Radix::TransactionOutput> tx1_outputs;
        tx1_outputs.push_back({5, bobKeys.getAddress()}); // 5 RDX a Bob
        
        // Calcular el cambio para Alice
        double changeAmount = aliceCoinbaseAmount - 5; 
        if (changeAmount > 0) {
            tx1_outputs.push_back({changeAmount, aliceKeys.getAddress()}); // Cambio de vuelta a Alice
        }

        // CORRECCIÓN: Usar el constructor de Transaction con inputs y outputs
        Radix::Transaction tx1(tx1_inputs, tx1_outputs, false); 
        tx1.sign(aliceKeys); // Alice firma la transacción
        std::cout << "  Transaccion 1 firmada por Alice. ID: " << tx1.id << std::endl;
        
        try {
            blockchain.addTransaction(tx1);
            std::cout << "  Transaccion 1 anadida a la piscina de transacciones pendientes." << std::endl;
        } catch (const std::runtime_error& e) {
            std::cerr << "Error al añadir Transaccion 1: " << e.what() << std::endl;
        }
        
        // Minar el primer bloque con la transacción de Alice
        std::cout << "\nIniciando mineria del primer bloque. Minero: " << bobKeys.getAddress() << std::endl;
        blockchain.minePendingTransactions(bobKeys.getAddress()); // Bob mina el bloque
        std::cout << "Primer bloque minado y anadido a la cadena." << std::endl;
        std::cout << "\n--- Informacion del Bloque #" << blockchain.getChainSize() - 1 << " ---" << std::endl; 
        std::cout << blockchain.getLatestBlock().toString() << std::endl;

        // --- INICIO DE PRUEBA DE UTXO YA GASTADA ---
        std::cout << "\n--- Prueba de Gasto de UTXO ya Gastada ---" << std::endl;
        std::cout << "Creando Transaccion de Prueba: Alice intenta gastar la misma UTXO (de su coinbase) de nuevo." << std::endl;

        std::vector<Radix::TransactionInput> tx_spent_utxo_inputs;
        // Alice intenta usar la misma UTXO de la coinbase que ya gastó en tx1
        tx_spent_utxo_inputs.push_back({aliceCoinbaseTxId, 0, Radix::Signature(), aliceKeys.getPublicKey()});

        std::vector<Radix::TransactionOutput> tx_spent_utxo_outputs;
        tx_spent_utxo_outputs.push_back({1, bobKeys.getAddress()}); // Alice intenta enviar 1 RDX a Bob

        Radix::Transaction tx_spent_utxo(tx_spent_utxo_inputs, tx_spent_utxo_outputs, false);
        tx_spent_utxo.sign(aliceKeys); // Alice firma la transacción

        std::cout << "  Transaccion de Prueba firmada por Alice. ID: " << tx_spent_utxo.id << std::endl;

        try {
            blockchain.addTransaction(tx_spent_utxo);
            std::cout << "  ERROR: La transaccion de prueba fue anadida a la piscina de transacciones pendientes (esto no deberia ocurrir)." << std::endl;
        } catch (const std::runtime_error& e) {
            std::cerr << "  EXITO: Error esperado al añadir transaccion de prueba (UTXO ya gastada): " << e.what() << std::endl;
        }
        // --- FIN DE PRUEBA DE UTXO YA GASTADA ---


        // Transacción 2: Bob envía 2 RDX a Alice.
        std::cout << "\nCreando Transaccion 2: Bob envia 2 RDX a Alice." << std::endl;

        // Buscar la UTXO que Bob recibió de Alice en tx1
        const Radix::Block& prevBlock = blockchain.getLatestBlock();
        // tx1_in_block es la transacción de Alice a Bob en el bloque anterior.
        // Asumimos que es la segunda transacción en el bloque (índice 1) después de la coinbase del minero.
        if (prevBlock.transactions.size() < 2) {
            throw std::runtime_error("El bloque anterior no contiene suficientes transacciones para la demo (esperaba tx1).");
        }
        const Radix::Transaction& tx1_in_block = prevBlock.transactions[1]; 
        
        // Encontrar la salida de tx1_in_block que pertenece a Bob
        std::string bobReceivedTxId = tx1_in_block.id;
        int bobOutputIndex = -1;
        double bobReceivedAmount = 0;
        for (size_t i = 0; i < tx1_in_block.outputs.size(); ++i) {
            if (tx1_in_block.outputs[i].recipientAddress == bobKeys.getAddress()) {
                bobOutputIndex = i;
                bobReceivedAmount = tx1_in_block.outputs[i].amount;
                break;
            }
        }
        if (bobOutputIndex == -1) {
            throw std::runtime_error("No se encontro la UTXO de Bob en la transaccion anterior.");
        }
        
        std::vector<Radix::TransactionInput> tx2_inputs;
        tx2_inputs.push_back({bobReceivedTxId, bobOutputIndex, Radix::Signature(), bobKeys.getPublicKey()}); // Gasta la UTXO de Bob

        std::vector<Radix::TransactionOutput> tx2_outputs;
        tx2_outputs.push_back({2, aliceKeys.getAddress()}); // 2 RDX a Alice
        // Cambio para Bob
        double bobChangeAmount = bobReceivedAmount - 2; 
        if (bobChangeAmount > 0) {
            tx2_outputs.push_back({bobChangeAmount, bobKeys.getAddress()}); // Cambio de vuelta a Bob
        }

        // CORRECCIÓN: Usar el constructor de Transaction con inputs y outputs
        Radix::Transaction tx2(tx2_inputs, tx2_outputs, false); 
        tx2.sign(bobKeys); // Bob firma la transacción
        std::cout << "  Transaccion 2 firmada por Bob. ID: " << tx2.id << std::endl;
        
        try {
            blockchain.addTransaction(tx2);
            std::cout << "  Transaccion 2 anadida a la piscina de transacciones pendientes." << std::endl;
        } catch (const std::runtime_error& e) {
            std::cerr << "Error al añadir Transaccion 2: " << e.what() << std::endl;
        }

        // Minar el segundo bloque con la transacción de Bob
        std::cout << "\nIniciando mineria del segundo bloque. Minero: " << aliceKeys.getAddress() << std::endl;
        blockchain.minePendingTransactions(aliceKeys.getAddress()); // Alice mina el bloque
        std::cout << "Segundo bloque minado y anadido a la cadena." << std::endl;
        std::cout << "\n--- Informacion del Bloque #" << blockchain.getChainSize() - 1 << " ---" << std::endl; 
        std::cout << blockchain.getLatestBlock().toString() << std::endl;


        std::cout << "\n--- Estado Final de la Blockchain ---" << std::endl;
        blockchain.printChain();

        std::cout << "\nValidando la integridad de toda la Blockchain..." << std::endl;
        if (blockchain.isChainValid()) {
            std::cout << "La Blockchain es VALIDA! Todos los bloques y hashes son correctos." << std::endl;
        } else {
            std::cout << "La Blockchain es INVALIDA! Se detectaron inconsistencias." << std::endl;
        }

        // Mostrar balances (ahora usan el UTXOSet)
        std::cout << "\n--- Balances Finales ---" << std::endl;
        std::cout << "Balance de Alice: " << blockchain.getBalanceOfAddress(aliceKeys.getAddress()) << " RDX" << std::endl;
        std::cout << "Balance de Bob: " << blockchain.getBalanceOfAddress(bobKeys.getAddress()) << " RDX" << std::endl;


    } catch (const std::runtime_error& e) {
        std::cerr << "terminate called after throwing an instance of 'std::runtime_error'" << std::endl;
        std::cerr << "  what():  " << e.what() << std::endl;
        ERR_print_errors_fp(stderr); // Imprimir errores detallados de OpenSSL si están disponibles
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Se capturo una excepcion inesperada: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "\n¡Radix Blockchain Core finalizado!" << std::endl;

    // ---- LIBERACIÓN DE RECURSOS DE OPENSSL (opcional pero buena práctica) ----
    OSSL_PROVIDER_unload(default_provider); 
    ERR_free_strings();
    // --------------------------------------------------------------------------

    return 0;
}
