#include <iostream>
#include <string>
#include <vector>
#include <memory> // Para std::unique_ptr
#include <map>    // Para std::map
#include <cstdint> // Para uint64_t

#include "blockchain.h"
#include "block.h"
#include "transaction.h"
#include "crypto.h"       // Para KeyPair
#include "randomx_util.h" // Para RandomXContext

// ¡NUEVAS INCLUSIONES!
#include "base58.h"         // Para Radix::Base58::encode
#include <openssl/provider.h> // Para OSSL_PROVIDER_load
#include "money_util.h"     // ¡NUEVO! Para RDX_DECIMAL_FACTOR y formatRadsToRDX

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

    // Crear una instancia de la blockchain con una dificultad de 1
    Radix::Blockchain radixChain(1, rxContext); // Pasamos la referencia a rxContext

    // Imprimir información del Bloque Génesis
    std::cout << "--- Información del Bloque Genesis ---\n";
    std::cout << radixChain.getLatestBlock().toString() << "\n";


    // --- Demostración de Criptografía (OpenSSL) ---
    std::cout << "--- Demostración de Criptografía (OpenSSL) ---\n";

    // Generar un par de claves para Alice
    Radix::KeyPair aliceKeys;
    std::cout << "Generando par de claves para Alice:\n";
    std::cout << "  Private Key (Base58): " << Radix::Base58::encode(std::vector<unsigned char>(aliceKeys.getPrivateKey().begin(), aliceKeys.getPrivateKey().end())) << "\n";
    std::cout << "  Public Key (Hex):    " << Radix::toHexString(aliceKeys.getPublicKey()) << "\n";
    std::cout << "  Address:             " << aliceKeys.getAddress() << "\n\n";

    // Generar un par de claves para Bob
    Radix::KeyPair bobKeys;
    std::cout << "Generando par de claves para Bob...\n";
    std::cout << "  Private Key (Base58): " << Radix::Base58::encode(std::vector<unsigned char>(bobKeys.getPrivateKey().begin(), bobKeys.getPrivateKey().end())) << "\n";
    std::cout << "  Public Key (Hex):    " << Radix::toHexString(bobKeys.getPublicKey()) << "\n";
    std::cout << "  Address:             " << bobKeys.getAddress() << "\n\n";

    // Demostración de firma y verificación
    std::string message = "Este es un mensaje de prueba para la firma digital.";
    Radix::RandomXHash messageHash = Radix::SHA256(message);
    std::cout << "Mensaje original para firmar: \"" << message << "\"\n";
    std::cout << "Hash del mensaje (para firma): " << Radix::toHexString(messageHash) << "\n";

    Radix::Signature aliceSignature = aliceKeys.sign(messageHash);
    std::cout << "Firma de Alice: " << Radix::toHexString(aliceSignature) << "\n";

    if (Radix::KeyPair::verify(aliceKeys.getPublicKey(), messageHash, aliceSignature)) {
        std::cout << "VERIFICACION DE FIRMA: Exitosa! La firma es valida.\n\n";
    } else {
        std::cout << "VERIFICACION DE FIRMA: Fallida! La firma NO es valida.\n\n";
    }

    // Intentar verificar la firma de Alice con la clave pública de Bob (debería fallar)
    std::cout << "Intentando verificar la firma de Alice con la clave publica de Bob (esperado: FALLO)...\n";
    if (Radix::KeyPair::verify(bobKeys.getPublicKey(), messageHash, aliceSignature)) {
        std::cout << "VERIFICACION DE FIRMA (con clave de Bob): Exitosa! (Incorrecto)\n\n";
    } else {
        std::cout << "VERIFICACION DE FIRMA (con clave de Bob): Fallida! (Correcto)\n\n";
    }


    // --- Demostración de Transacciones y Minería (con UTXO) ---
    std::cout << "--- Demostracion de Transacciones y Mineria (con UTXO) ---\n\n";

    // Minar un bloque para Alice para darle fondos (recompensa de minería)
    std::cout << "Minando un bloque inicial para Alice para darle fondos...\n";
    radixChain.minePendingTransactions(aliceKeys.getAddress());
    // Corrección: Usar Radix::formatRadsToRDX
    std::cout << "Bloque inicial minado para Alice. Balance de Alice: " << Radix::formatRadsToRDX(radixChain.getBalanceOfAddress(aliceKeys.getAddress())) << " RDX\n\n";

    // Imprimir el Bloque #1 (el primer bloque minado)
    std::cout << "--- Informacion del Bloque #1 ---\n";
    std::cout << radixChain.getLatestBlock().toString() << "\n";


    // --- Transacción 1: Alice envía 5 RDX a Bob ---
    std::cout << "Creando Transaccion 1: Alice envia 5 RDX a Bob.\n";
    std::vector<Radix::TransactionInput> tx1_inputs;
    std::vector<Radix::TransactionOutput> tx1_outputs;

    // Corrección: Usar Radix::RDX_DECIMAL_FACTOR
    uint64_t amountToSendTx1 = 5ULL * Radix::RDX_DECIMAL_FACTOR; // 5 RDX en rads
    uint64_t aliceInitialBalance = radixChain.getBalanceOfAddress(aliceKeys.getAddress());

    // Alice gasta su UTXO de la recompensa de minería (del Bloque #1)
    std::string aliceCoinbaseTxId = radixChain.getLatestBlock().transactions[0].id;
    uint64_t aliceCoinbaseOutputIndex = 0; 

    tx1_inputs.push_back({aliceCoinbaseTxId, aliceCoinbaseOutputIndex, aliceKeys.getPublicKey(), Radix::Signature()}); // Firma vacía por ahora

    // Salidas: Monto para Bob y el cambio de vuelta a Alice
    tx1_outputs.push_back({amountToSendTx1, bobKeys.getAddress()}); 
    tx1_outputs.push_back({aliceInitialBalance - amountToSendTx1, aliceKeys.getAddress()}); // Cambio de vuelta a Alice

    Radix::Transaction tx1(tx1_inputs, tx1_outputs);
    tx1.sign(aliceKeys.getPrivateKey(), aliceKeys.getPublicKey(), radixChain.getUtxoSet()); // Alice firma la transacción

    std::cout << "  Transaccion 1 firmada por Alice. ID: " << tx1.id << "\n";
    radixChain.addTransaction(tx1);
    std::cout << "  Transaccion 1 anadida a la piscina de transacciones pendientes.\n\n";

    // Minar el primer bloque (que contendrá la Transacción 1)
    std::cout << "Iniciando mineria del primer bloque. Minero: " << bobKeys.getAddress() << "\n";
    radixChain.minePendingTransactions(bobKeys.getAddress()); // Bob mina el bloque
    std::cout << "Primer bloque minado y anadido a la cadena.\n\n";

    // Imprimir el Bloque #2
    std::cout << "--- Informacion del Bloque #2 ---\n";
    std::cout << radixChain.getLatestBlock().toString() << "\n";


    // --- Prueba de Gasto de UTXO ya Gastada ---
    std::cout << "--- Prueba de Gasto de UTXO ya Gastada ---\n";
    std::cout << "Creando Transaccion de Prueba: Alice intenta gastar la misma UTXO (de su coinbase) de nuevo.\n";
    std::vector<Radix::TransactionInput> tx_spent_utxo_inputs;
    std::vector<Radix::TransactionOutput> tx_spent_utxo_outputs;

    tx_spent_utxo_inputs.push_back({aliceCoinbaseTxId, aliceCoinbaseOutputIndex, aliceKeys.getPublicKey(), Radix::Signature()});
    // Corrección: Usar Radix::RDX_DECIMAL_FACTOR
    tx_spent_utxo_outputs.push_back({1ULL * Radix::RDX_DECIMAL_FACTOR, bobKeys.getAddress()});

    Radix::Transaction tx_spent_utxo(tx_spent_utxo_inputs, tx_spent_utxo_outputs);
    
    try {
        tx_spent_utxo.sign(aliceKeys.getPrivateKey(), aliceKeys.getPublicKey(), radixChain.getUtxoSet()); // Alice firma la transacción
        std::cout << "  Transaccion de Prueba firmada por Alice. ID: " << tx_spent_utxo.id << "\n";
        radixChain.addTransaction(tx_spent_utxo);
        std::cout << "  ERROR: Transaccion de prueba añadida a pendientes (no deberia haber sido). \n\n";
    } catch (const std::runtime_error& e) {
        std::cout << "  EXITO: Error esperado al añadir transaccion de prueba (UTXO ya gastada): " << e.what() << "\n\n";
    }


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
        std::cerr << "Error: La UTXO de Bob (" << utxoKeyBob << ") no se encontró en el UTXO Set." << std::endl;
        return 1; 
    }

    // Corrección: Usar Radix::RDX_DECIMAL_FACTOR
    uint64_t amountToSend = 2ULL * Radix::RDX_DECIMAL_FACTOR; // 2 RDX

    // Asegurarse de que Bob tiene suficientes fondos en esa UTXO
    if (bobInputAmount < amountToSend) {
        // Corrección: Usar Radix::formatRadsToRDX para el mensaje de error
        std::cerr << "Error: Bob no tiene suficientes fondos en la UTXO seleccionada para enviar " << Radix::formatRadsToRDX(amountToSend) << " RDX." << std::endl;
        return 1;
    }

    tx2_inputs.push_back({bobReceivedTxId, static_cast<uint64_t>(bobOutputIndex), bobKeys.getPublicKey(), Radix::Signature()}); // Gasta la UTXO de Bob

    // Salidas: Monto para Alice y el cambio de vuelta a Bob
    tx2_outputs.push_back({amountToSend, aliceKeys.getAddress()});
    tx2_outputs.push_back({bobInputAmount - amountToSend, bobKeys.getAddress()}); // Cambio de vuelta a Bob


    Radix::Transaction tx2(tx2_inputs, tx2_outputs);
    tx2.sign(bobKeys.getPrivateKey(), bobKeys.getPublicKey(), radixChain.getUtxoSet()); // Bob firma la transacción

    std::cout << "  Transaccion 2 firmada por Bob. ID: " << tx2.id << "\n";
    radixChain.addTransaction(tx2);
    std::cout << "  Transaccion 2 anadida a la piscina de transacciones pendientes.\n\n";

    // Minar el segundo bloque (que contendrá la Transacción 2 y el Halving)
    std::cout << "Iniciando mineria del segundo bloque. Minero: " << aliceKeys.getAddress() << "\n";
    radixChain.minePendingTransactions(aliceKeys.getAddress()); // Alice mina el bloque
    std::cout << "Segundo bloque minado y anadido a la cadena.\n\n";

    // Imprimir el Bloque #3
    std::cout << "--- Informacion del Bloque #3 ---\n";
    std::cout << radixChain.getLatestBlock().toString() << "\n";


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
    // Corrección: Usar Radix::formatRadsToRDX para imprimir el balance
    std::cout << "Balance de Alice: " << Radix::formatRadsToRDX(radixChain.getBalanceOfAddress(aliceKeys.getAddress())) << " RDX\n";
    std::cout << "Balance de Bob: " << Radix::formatRadsToRDX(radixChain.getBalanceOfAddress(bobKeys.getAddress())) << " RDX\n";

    std::cout << "\n¡Radix Blockchain Core finalizado!\n";

    return 0;
}