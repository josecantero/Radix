// main.cpp
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
        // Inicializar caché y dataset de RandomX
        rxContext.initCache({}); // Seed vacío por simplicidad
        rxContext.initDataset();
        
        std::cout << "Contexto de RandomX listo." << std::endl << std::flush;

        // Ahora el constructor de Blockchain toma la dificultad y el contexto RandomX
        unsigned int blockchain_difficulty = 10; 
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

        // --- Demostración de Transacciones y Minería (con UTXO) ---
        std::cout << "\n--- Demostracion de Transacciones y Mineria (con UTXO) ---" << std::endl << std::flush;

        // Para demostrar el UTXO, Alice necesita fondos iniciales.
        // Simularemos que el Bloque Génesis le da fondos a Alice (esto no es estándar, pero para la demo).
        // En un sistema real, los fondos iniciales se obtendrían de una transacción coinbase minada.
        // Para simplificar la demo, vamos a minar un bloque inicial para Alice.
        std::cout << "\nMinando un bloque inicial para Alice para darle fondos..." << std::endl << std::flush;
        blockchain.minePendingTransactions(aliceKeys.getAddress()); // Alice mina un bloque (solo con coinbase)
        std::cout << "Bloque inicial minado para Alice. Balance de Alice: " << blockchain.getBalanceOfAddress(aliceKeys.getAddress()) << " RDX" << std::endl << std::flush;
        std::cout << "\n--- Informacion del Bloque #" << blockchain.getChainSize() - 1 << " ---" << std::endl << std::flush; 
        std::cout << blockchain.getLatestBlock().toString() << std::endl << std::flush;


        // Transacción 1: Alice envía 5 RDX a Bob.
        // Alice necesita gastar una UTXO. La UTXO de la coinbase del bloque anterior.
        std::cout << "\nCreando Transaccion 1: Alice envia 5 RDX a Bob." << std::endl << std::flush;
        
        // Asumimos que la coinbase de Alice es la única UTXO que tiene.
        // Necesitamos el ID de la transacción coinbase del último bloque minado por Alice.
        // La coinbase es la primera transacción en el bloque.
        const Radix::Block& lastBlock = blockchain.getLatestBlock();
        if (lastBlock.transactions.empty() || !lastBlock.transactions[0].isCoinbase) {
             throw std::runtime_error("El ultimo bloque no contiene una transaccion coinbase esperada.");
        }
        std::string aliceCoinbaseTxId = lastBlock.transactions[0].id;
        
        std::vector<Radix::TransactionInput> tx1_inputs;
        // Referencia a la UTXO de la coinbase de Alice (ID de la coinbase, índice 0)
        tx1_inputs.push_back({aliceCoinbaseTxId, 0, Radix::Signature(), aliceKeys.getPublicKey()}); 

        std::vector<Radix::TransactionOutput> tx1_outputs;
        tx1_outputs.push_back({5, bobKeys.getAddress()}); // 5 RDX a Bob
        // Calculamos el cambio para Alice. Asumiendo que la coinbase fue de 100 RDX.
        // En un sistema real, se buscarían UTXOs que sumen al menos el monto a enviar.
        double changeAmount = 100 - 5; // 100 - 5 = 95 RDX (CORREGIDO: Acceso directo al valor de la recompensa)
        if (changeAmount > 0) {
            tx1_outputs.push_back({changeAmount, aliceKeys.getAddress()}); // Cambio de vuelta a Alice
        }

        Radix::Transaction tx1(tx1_inputs, tx1_outputs); // Usa el nuevo constructor de UTXO
        tx1.sign(aliceKeys); // Alice firma la transacción
        std::cout << "  Transaccion 1 firmada por Alice. ID: " << tx1.id << std::endl << std::flush;
        blockchain.addTransaction(tx1);
        std::cout << "  Transaccion 1 anadida a la piscina de transacciones pendientes." << std::endl << std::flush;
        
        // Minar el primer bloque con la transacción de Alice
        std::cout << "\nIniciando mineria del primer bloque. Minero: " << bobKeys.getAddress() << std::endl << std::flush;
        blockchain.minePendingTransactions(bobKeys.getAddress()); // Bob mina el bloque
        std::cout << "Primer bloque minado y anadido a la cadena." << std::endl << std::flush;
        std::cout << "\n--- Informacion del Bloque #" << blockchain.getChainSize() - 1 << " ---" << std::endl << std::flush; 
        std::cout << blockchain.getLatestBlock().toString() << std::endl << std::flush;

        // Transacción 2: Bob envía 2 RDX a Alice.
        // Bob necesita gastar una UTXO. La UTXO que recibió de Alice en tx1.
        std::cout << "\nCreando Transaccion 2: Bob envia 2 RDX a Alice." << std::endl << std::flush;

        // Buscar la UTXO que Bob recibió de Alice en tx1
        // La transacción tx1 fue la segunda en el bloque anterior (índice 1, después de la coinbase de Bob).
        const Radix::Block& prevBlock = blockchain.getLatestBlock();
        if (prevBlock.transactions.size() < 2) {
            throw std::runtime_error("El bloque anterior no contiene suficientes transacciones para la demo.");
        }
        const Radix::Transaction& tx1_in_block = prevBlock.transactions[1]; // Suponemos que tx1 es la segunda transacción
        std::string bobReceivedTxId = tx1_in_block.id;
        // Bob recibió 5 RDX de Alice, esa es la salida de tx1_in_block con índice 0 (si no hay cambio a Alice)
        // Ojo: si tx1_outputs tenía cambio, la salida de Bob sería la primera (índice 0).
        // Si tx1_outputs sólo tenía una salida a Bob, entonces el índice es 0.
        // Si tx1_outputs tenía una salida a Bob y una de cambio a Alice, la salida a Bob es outputs[0].
        // Validamos que sea la UTXO de Bob.
        if (tx1_in_block.outputs.empty() || tx1_in_block.outputs[0].recipientAddress != bobKeys.getAddress()) {
             throw std::runtime_error("La transaccion 1 en el bloque no contiene la UTXO esperada para Bob.");
        }
        
        std::vector<Radix::TransactionInput> tx2_inputs;
        tx2_inputs.push_back({bobReceivedTxId, 0, Radix::Signature(), bobKeys.getPublicKey()}); // Gasta la UTXO de 5 RDX de Bob

        std::vector<Radix::TransactionOutput> tx2_outputs;
        tx2_outputs.push_back({2, aliceKeys.getAddress()}); // 2 RDX a Alice
        // Cambio para Bob: 5 RDX (recibido) - 2 RDX (enviado) = 3 RDX
        double bobChangeAmount = 5 - 2; 
        if (bobChangeAmount > 0) {
            tx2_outputs.push_back({bobChangeAmount, bobKeys.getAddress()}); // Cambio de vuelta a Bob
        }

        Radix::Transaction tx2(tx2_inputs, tx2_outputs); // Usa el nuevo constructor de UTXO
        tx2.sign(bobKeys); // Bob firma la transacción
        std::cout << "  Transaccion 2 firmada por Bob. ID: " << tx2.id << std::endl << std::flush;
        blockchain.addTransaction(tx2);
        std::cout << "  Transaccion 2 anadida a la piscina de transacciones pendientes." << std::endl << std::flush;

        // Minar el segundo bloque con la transacción de Bob
        std::cout << "\nIniciando mineria del segundo bloque. Minero: " << aliceKeys.getAddress() << std::endl << std::flush;
        blockchain.minePendingTransactions(aliceKeys.getAddress()); // Alice mina el bloque
        std::cout << "Segundo bloque minado y anadido a la cadena." << std::endl << std::flush;
        std::cout << "\n--- Informacion del Bloque #" << blockchain.getChainSize() - 1 << " ---" << std::endl << std::flush; 
        std::cout << blockchain.getLatestBlock().toString() << std::endl << std::flush;

        std::cout << "\n--- Estado Final de la Blockchain ---" << std::endl << std::flush;
        blockchain.printChain();

        std::cout << "\nValidando la integridad de toda la Blockchain..." << std::endl << std::flush;
        if (blockchain.isChainValid()) {
            std::cout << "La Blockchain es VALIDA! Todos los bloques y hashes son correctos." << std::endl << std::flush;
        } else {
            std::cout << "La Blockchain es INVALIDA! Se detectaron inconsistencias." << std::endl << std::flush;
        }

        // Mostrar balances (ahora usan el UTXOSet)
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
