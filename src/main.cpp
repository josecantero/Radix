#include <iostream>
#include <string>
#include <vector>
#include <memory> // Para std::unique_ptr
#include <map>    // Para std::map
#include <cstdint> // Para uint64_t
#include <fstream> // Necesario para la persistencia

#include "blockchain.h"
#include "block.h"
#include "transaction.h"
#include "crypto.h"       // Para KeyPair
#include "randomx_util.h" // Para RandomXContext

// ¡NUEVAS INCLUSIONES!
#include "base58.h"         // Para Radix::Base58::encode
#include <openssl/provider.h> // Para OSSL_PROVIDER_load
#include "money_util.h"     // Para RDX_DECIMAL_FACTOR y formatRadsToRDX

// Define el nombre del archivo de persistencia
const std::string RADIX_CHAIN_FILE = "radix_blockchain.dat";

// Función para inicializar los proveedores de OpenSSL
void initializeOpenSSL() {
    // Cargar los proveedores predeterminados
    OSSL_PROVIDER* default_provider = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER* base_provider = OSSL_PROVIDER_load(NULL, "base");

    if (default_provider && base_provider) {
        std::cout << "Proveedores OpenSSL cargados exitosamente." << std::endl;
    } else {
        std::cerr << "Error al cargar los proveedores OpenSSL." << std::endl;
        // Manejo de errores más robusto si es necesario
    }
}

int main() {
    initializeOpenSSL(); // Inicializar OpenSSL al inicio

    std::cout << "Iniciando Radix Blockchain Core...\n" << std::endl;

    // Inicializar el contexto de RandomX
    Radix::RandomXContext rxContext;

    // Crear instancias de claves para la demostración
    Radix::KeyPair aliceKeys;
    Radix::KeyPair bobKeys;

    // --- Persistencia: Cargar la cadena ---
    // Crear una instancia de la blockchain con una dificultad de 1 (si es nueva)
    Radix::Blockchain radixChain(1, rxContext); 
    bool chainLoaded = radixChain.loadChain(RADIX_CHAIN_FILE);
    // ---------------------------------------

    std::cout << "Estado de la cadena: " << (chainLoaded ? "Cargada (" : "Nueva (") << radixChain.getChainSize() << " bloques).\n";
    std::cout << "------------------------------------------\n";

    // Minería inicial y bienvenida a Alice, solo si es una cadena nueva o recién cargada sin bloques minados.
    if (radixChain.getChainSize() <= 1) { // 1 significa solo el bloque génesis
        std::cout << "--- Información del Bloque Genesis ---\n";
        std::cout << radixChain.getLatestBlock().toString() << "\n";

        // Minar un bloque para Alice para darle fondos (recompensa de minería)
        std::cout << "Minando un bloque inicial para Alice para darle fondos...\n";
        radixChain.minePendingTransactions(aliceKeys.getAddress());
        std::cout << "Bloque inicial minado para Alice. Balance de Alice: " << Radix::formatRadsToRDX(radixChain.getBalanceOfAddress(aliceKeys.getAddress())) << " RDX\n\n";

        // Imprimir el Bloque #1 (el primer bloque minado)
        std::cout << "--- Informacion del Bloque #1 ---\n";
        std::cout << radixChain.getLatestBlock().toString() << "\n";
    }


    // --- Demostración de Criptografía (OpenSSL) --- (Mantenido para mostrar las claves)
    std::cout << "--- Demostración de Criptografía (OpenSSL) ---\n";

    std::cout << "Claves de Alice (Address): " << aliceKeys.getAddress() << "\n";
    std::cout << "Claves de Bob (Address):   " << bobKeys.getAddress() << "\n\n";

    // Demostración de firma y verificación (El resto del código criptográfico se mantiene igual)
    std::string message = "Este es un mensaje de prueba para la firma digital.";
    Radix::RandomXHash messageHash = Radix::SHA256(message);
    
    Radix::Signature aliceSignature = aliceKeys.sign(messageHash);
    
    if (Radix::KeyPair::verify(aliceKeys.getPublicKey(), messageHash, aliceSignature)) {
        std::cout << "VERIFICACION DE FIRMA: Exitosa! La firma es valida.\n\n";
    } else {
        std::cout << "VERIFICACION DE FIRMA: Fallida! La firma NO es valida.\n\n";
    }

    // El resto del código de demostración de transacciones sigue asumiendo que el bloque inicial ya se minó.

    // --- Demostración de Transacciones y Minería (con UTXO) ---
    std::cout << "--- Demostracion de Transacciones y Mineria (con UTXO) ---\n\n";
    
    // Si la cadena ya estaba avanzada, necesitamos adaptar los IDs de transacción para que la demo funcione.
    // Para simplificar, la demostración de transacciones debe ser reescrita para buscar UTXOs disponibles
    // en lugar de asumir que la UTXO de coinbase está en el Bloque #1.
    
    // NOTA: Para este ejemplo, solo ejecutaremos las transacciones si la cadena no es demasiado larga,
    // o el código de la demo deberá ser reescrito para buscar dinámicamente las UTXOs correctas.
    // Asumiremos que si la cadena tiene menos de 4 bloques, ejecutamos el siguiente paso de la demo.
    
    if (radixChain.getChainSize() < 4) {
        // ... (El código de Transacción 1 y Transacción 2 sigue aquí)
        
        // El código de la demo debe buscar dinámicamente la UTXO más reciente de Alice
        // en lugar de asumir el Bloque #1. Simplificaremos asumiendo la UTXO más grande
        // para la dirección de Alice.
        
        // Lógica de búsqueda de la UTXO más grande de Alice para la demo:
        std::string aliceUtxoKey = "";
        uint64_t aliceLargestUtxoAmount = 0;
        
        for (const auto& pair : radixChain.getUtxoSet()) {
            const Radix::TransactionOutput& utxo = pair.second;
            if (utxo.recipientAddress == aliceKeys.getAddress() && utxo.amount > aliceLargestUtxoAmount) {
                aliceLargestUtxoAmount = utxo.amount;
                aliceUtxoKey = pair.first;
            }
        }
        
        if (aliceUtxoKey.empty()) {
            std::cerr << "Advertencia: Alice no tiene UTXOs disponibles para transacciones. Saltando la demo de transacciones.\n";
        } else {
            // Analizar la clave para obtener ID de TX anterior e índice de salida
            std::string aliceCoinbaseTxId = aliceUtxoKey.substr(0, aliceUtxoKey.find(':'));
            uint64_t aliceCoinbaseOutputIndex = std::stoull(aliceUtxoKey.substr(aliceUtxoKey.find(':') + 1));
            uint64_t aliceInitialBalance = aliceLargestUtxoAmount; // El monto de la UTXO seleccionada

            // --- Transacción 1: Alice envía 5 RDX a Bob ---
            std::cout << "Creando Transaccion 1: Alice envia 5 RDX a Bob (usando UTXO: " << aliceUtxoKey << ").\n";
            std::vector<Radix::TransactionInput> tx1_inputs;
            std::vector<Radix::TransactionOutput> tx1_outputs;

            uint64_t amountToSendTx1 = 5ULL * Radix::RDX_DECIMAL_FACTOR; // 5 RDX en rads

            tx1_inputs.push_back({aliceCoinbaseTxId, aliceCoinbaseOutputIndex, aliceKeys.getPublicKey(), Radix::Signature()}); // Firma vacía por ahora

            // Salidas: Monto para Bob y el cambio de vuelta a Alice
            tx1_outputs.push_back({amountToSendTx1, bobKeys.getAddress()}); 
            tx1_outputs.push_back({aliceInitialBalance - amountToSendTx1, aliceKeys.getAddress()}); // Cambio de vuelta a Alice

            Radix::Transaction tx1(tx1_inputs, tx1_outputs);
            tx1.sign(aliceKeys.getPrivateKey(), aliceKeys.getPublicKey(), radixChain.getUtxoSet()); // Alice firma la transacción

            std::cout << "  Transaccion 1 firmada por Alice. ID: " << tx1.id << "\n";
            radixChain.addTransaction(tx1);
            std::cout << "  Transaccion 1 anadida a la piscina de transacciones pendientes.\n\n";

            // Minar el primer bloque de la demo (que contendrá la Transacción 1)
            std::cout << "Iniciando mineria del bloque. Minero: " << bobKeys.getAddress() << "\n";
            radixChain.minePendingTransactions(bobKeys.getAddress()); // Bob mina el bloque
            std::cout << "Bloque minado y anadido a la cadena. (Tamanio: " << radixChain.getChainSize() << ").\n\n";

            // --- Transacción 2: Bob envia 2 RDX a Alice ---
            std::cout << "Creando Transaccion 2: Bob envia 2 RDX a Alice.\n";
            std::vector<Radix::TransactionInput> tx2_inputs;
            std::vector<Radix::TransactionOutput> tx2_outputs;

            // Bob gasta la UTXO que recibió de Alice en la Transacción 1
            std::string bobReceivedTxId = tx1.id;
            int bobOutputIndex = 0; // La salida de 5 RDX para Bob es la primera salida de tx1

            // Obtenemos la UTXO que Bob recibió
            std::string utxoKeyBob = bobReceivedTxId + ":" + std::to_string(bobOutputIndex);
            uint64_t bobInputAmount = 0; 
            auto it_bob_utxo = radixChain.getUtxoSet().find(utxoKeyBob);

            if (it_bob_utxo != radixChain.getUtxoSet().end()) {
                bobInputAmount = it_bob_utxo->second.amount;
            } else {
                std::cerr << "Error: La UTXO de Bob (" << utxoKeyBob << ") no se encontro en el UTXO Set. Saltando T2." << std::endl;
            }
            
            if (bobInputAmount > 0) {
                uint64_t amountToSend = 2ULL * Radix::RDX_DECIMAL_FACTOR; // 2 RDX

                tx2_inputs.push_back({bobReceivedTxId, static_cast<uint64_t>(bobOutputIndex), bobKeys.getPublicKey(), Radix::Signature()}); // Gasta la UTXO de Bob

                // Salidas: Monto para Alice y el cambio de vuelta a Bob
                tx2_outputs.push_back({amountToSend, aliceKeys.getAddress()});
                tx2_outputs.push_back({bobInputAmount - amountToSend, bobKeys.getAddress()}); // Cambio de vuelta a Bob

                Radix::Transaction tx2(tx2_inputs, tx2_outputs);
                tx2.sign(bobKeys.getPrivateKey(), bobKeys.getPublicKey(), radixChain.getUtxoSet()); // Bob firma la transacción

                std::cout << "  Transaccion 2 firmada por Bob. ID: " << tx2.id << "\n";
                radixChain.addTransaction(tx2);
                std::cout << "  Transaccion 2 anadida a la piscina de transacciones pendientes.\n\n";

                // Minar el segundo bloque de la demo (que contendrá la Transacción 2 y el Halving)
                std::cout << "Iniciando mineria del segundo bloque de la demo. Minero: " << aliceKeys.getAddress() << "\n";
                radixChain.minePendingTransactions(aliceKeys.getAddress()); // Alice mina el bloque
                std::cout << "Bloque minado y anadido a la cadena. (Tamanio: " << radixChain.getChainSize() << ").\n\n";
            }
        }
    } else {
        std::cout << "Cadena avanzada. Saltando la demo de transacciones para mantener la consistencia.\n\n";
    }

    // --- Estado Final de la Blockchain ---
    std::cout << "--- Estado Final de la Blockchain ---\n";
    radixChain.printChain();
    std::cout << "\n";

    // Validar la integridad de toda la cadena
    std::cout << "Validando la integridad de toda la Blockchain...\n";
    if (radixChain.isChainValid()) {
        std::cout << "La Blockchain es VALIDA! No se detectaron inconsistencias.\n\n";
    } else {
        std::cout << "La Blockchain es INVALIDA! Se detectaron inconsistencias.\n\n";
    }

    // Balances finales
    std::cout << "--- Balances Finales ---\n";
    std::cout << "Balance de Alice: " << Radix::formatRadsToRDX(radixChain.getBalanceOfAddress(aliceKeys.getAddress())) << " RDX\n";
    std::cout << "Balance de Bob: " << Radix::formatRadsToRDX(radixChain.getBalanceOfAddress(bobKeys.getAddress())) << " RDX\n";

    // --- Persistencia: Guardar la cadena ---
    std::cout << "\nGuardando el estado final de la Blockchain en " << RADIX_CHAIN_FILE << "...\n";
    radixChain.saveChain(RADIX_CHAIN_FILE);
    // ---------------------------------------
    
    std::cout << "\n¡Radix Blockchain Core finalizado!\n";

    return 0;
}