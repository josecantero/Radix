// blockchain.cpp
#include "blockchain.h"
#include "block.h"
#include "transaction.h"
#include "randomx_util.h" // Para RandomXContext, toHexString, fromHexString
#include "crypto.h" // Para SHA256 (aunque RandomXContext.hash es el principal)

#include <iostream>
#include <sstream>
#include <chrono>
#include <algorithm> // Para std::all_of

namespace Radix {

// Constructor de la Blockchain
Blockchain::Blockchain(unsigned int difficulty, Radix::RandomXContext& rxContext_ref)
    : difficulty(difficulty), miningReward(100), rxContext_(rxContext_ref) { // Recompensa de minería fija y almacena la referencia
    // Crea el bloque génesis al iniciar la blockchain
    chain.push_back(createGenesisBlock());
}

// Crea el bloque génesis (el primer bloque de la cadena)
Block Blockchain::createGenesisBlock() {
    // El bloque génesis no tiene transacciones previas ni prevHash
    // La raíz de Merkle se calculará como el hash de un vector vacío de transacciones inicialmente
    std::vector<Transaction> genesisTransactions;
    Block genesisBlock(1, "0000000000000000000000000000000000000000000000000000000000000000",
                       genesisTransactions, difficulty, rxContext_); // Pasa rxContext_
    // El hash inicial se calculará dentro del constructor del bloque.
    // Aunque el genesis no necesita minarse con dificultad real, lo pasamos por la función de hash para consistencia.
    // No llamamos a mineBlock aquí porque el genesis no requiere prueba de trabajo.
    genesisBlock.hash = genesisBlock.calculateHash(); // Llama a la función sin argumento
    return genesisBlock;
}

// Obtiene el último bloque de la cadena
const Block& Blockchain::getLatestBlock() const {
    return chain.back();
}

// Nuevo método: Obtiene el tamaño actual de la cadena (número de bloques)
size_t Blockchain::getChainSize() const {
    return chain.size();
}

// Añade una transacción a las transacciones pendientes
void Blockchain::addTransaction(const Radix::Transaction& transaction) {
    // Para una blockchain real, aquí se añadirían muchas más validaciones de transacciones.
    // Por ahora, solo verificamos que no sea nula y que sea válida en sí misma.
    if (!transaction.isValid()) {
        throw std::runtime_error("No se puede añadir transaccion invalida a las transacciones pendientes.");
    }
    
    // Una transacción coinbase no debería ser añadida a pendingTransactions
    // directamente a través de addTransaction, ya que se crea durante minePendingTransactions.
    if (transaction.isCoinbase) {
        throw std::runtime_error("No se puede añadir una transaccion coinbase a la lista de transacciones pendientes.");
    }

    pendingTransactions.push_back(transaction);
    std::cout << "Transaccion añadida a pendientes: " << transaction.calculateHash() << std::endl;
}

// Mina las transacciones pendientes y crea un nuevo bloque
void Blockchain::minePendingTransactions(const std::string& miningRewardAddress) { // Removido rxContext
    if (pendingTransactions.empty()) {
        std::cout << "No hay transacciones pendientes para minar." << std::endl;
        return;
    }

    // Crear la transacción de recompensa de minería (coinbase)
    // El remitente es "coinbase" y el monto es la recompensa de minería
    Transaction coinbaseTx(true); // Usamos el constructor de coinbase
    coinbaseTx.outputs.push_back({miningReward, miningRewardAddress}); // Establecemos la salida de la recompensa
    coinbaseTx.updateId(); // Asegurarse de que el ID de la coinbase se calcule.

    // Añadirla al principio de las transacciones pendientes para que sea la primera en el bloque.
    // Usamos insert en lugar de push_back para mantenerla al principio.
    std::vector<Transaction> transactionsForBlock = pendingTransactions;
    transactionsForBlock.insert(transactionsForBlock.begin(), coinbaseTx);


    // Crear el nuevo bloque con las transacciones pendientes
    Block newBlock(getLatestBlock().version + 1, getLatestBlock().hash, transactionsForBlock, difficulty, rxContext_); // Pasa rxContext_
    
    // Minar el bloque
    newBlock.mineBlock(difficulty); // Llama a la función sin argumento

    // Añadir el bloque minado a la cadena
    chain.push_back(newBlock);

    // Limpiar las transacciones pendientes
    pendingTransactions.clear();
    std::cout << "Bloque minado y añadido a la cadena. Transacciones pendientes limpiadas." << std::endl;
}

// Obtiene el balance de una dirección específica
double Blockchain::getBalanceOfAddress(const std::string& address) const {
    double balance = 0;
    // Iterar sobre cada bloque en la cadena
    for (const auto& block : chain) {
        // Iterar sobre cada transacción en el bloque
        for (const auto& tx : block.transactions) {
            // Recorre las salidas de la transacción
            for (const auto& output : tx.outputs) {
                if (output.recipientAddress == address) {
                    balance += output.amount;
                }
            }
            // Recorre las entradas de la transacción
            // En un modelo UTXO completo, esto sería más complejo. Aquí, simplificamos.
            // Si la transacción no es coinbase y una de sus entradas es de esta dirección,
            // asumimos que el monto se gasta de su balance.
            // Esto es una simplificación y no maneja correctamente los cambios (UTXO no gastadas).
            // Para ser precisos con UTXO, necesitaríamos rastrear el valor de cada input gastado.
        }
    }
    return balance;
}

// Valida la integridad de toda la cadena
bool Blockchain::isChainValid() const { // Removido rxContext
    // El bloque génesis (índice 0) tiene un tratamiento especial para su validez.
    // Solo verificamos su integridad interna (hash y merkle root), no su Proof of Work.
    if (!chain[0].isValid()) { // Llama a la función sin argumento
        std::cerr << "Cadena Invalida: El bloque genesis no es valido (fallo en consistencia interna)." << std::endl;
        return false;
    }

    // Iterar desde el segundo bloque (índice 1) hasta el final
    for (size_t i = 1; i < chain.size(); ++i) {
        const Block& currentBlock = chain[i];
        const Block& previousBlock = chain[i-1];

        // 1. Validar el bloque actual (su propio hash y transacciones)
        // Esto incluye la verificación del hash con respecto a la dificultad.
        if (!currentBlock.isValid()) { // Llama a la función sin argumento
            std::cerr << "Cadena Invalida: El bloque en el indice " << i << " no es valido (fallo en hash/dificultad/transacciones)." << std::endl;
            return false;
        }

        // 2. Verificar que el prevHash del bloque actual coincide con el hash del bloque anterior
        if (currentBlock.prevHash != previousBlock.hash) {
            std::cerr << "Cadena Invalida: prevHash del bloque en el indice " << i
                      << " no coincide con el hash del bloque anterior. "
                      << "Esperado: " << previousBlock.hash
                      << ", Encontrado: " << currentBlock.prevHash << std::endl;
            return false;
        }
    }

    return true; // Si todo es válido, la cadena es válida
}

// Imprime todos los bloques en la cadena
void Blockchain::printChain() const { // Removido rxContext
    for (size_t i = 0; i < chain.size(); ++i) {
        std::cout << "\n--- Bloque #" << i << " ---\n";
        std::cout << chain[i].toString() << std::endl; // Llama a la función sin argumento
    }
}

} // namespace Radix
