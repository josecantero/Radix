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
#include <stdexcept> // Para std::runtime_error

namespace Radix {

// Constructor de la Blockchain
Blockchain::Blockchain(unsigned int difficulty, Radix::RandomXContext& rxContext_ref)
    : difficulty(difficulty), miningReward(100), rxContext_(rxContext_ref) { // Recompensa de minería fija y almacena la referencia
    // Crea el bloque génesis al iniciar la blockchain
    Block genesisBlock = createGenesisBlock();
    chain.push_back(genesisBlock);
    applyBlockTransactionsToUtxoSet(genesisBlock, utxoSet); // Procesa las transacciones del bloque génesis para inicializar el UTXOSet
    std::cout << "Blockchain inicializada y Bloque Genesis creado." << std::endl;
}

// Crea el bloque génesis (el primer bloque de la cadena)
Block Blockchain::createGenesisBlock() {
    // El bloque génesis no tiene transacciones previas ni prevHash
    std::vector<Transaction> genesisTransactions;
    
    // Transacción coinbase para el bloque génesis (recompensa inicial a una dirección arbitraria)
    // Usaremos la dirección de Alice (o cualquier otra) como la dirección de recompensa inicial para el Génesis.
    // Para este ejemplo, solo crearemos una transacción coinbase simple.
    // En una aplicación real, el bloque génesis puede tener una transacción coinbase predefinida.
    Transaction genesisCoinbaseTx("genesis_miner_address", miningReward, true); // Es una coinbase
    // El ID de la transacción y el UTXO ID de la salida se establecerán en el constructor de Transaction.
    genesisTransactions.push_back(genesisCoinbaseTx);

    // FIX: Add rxContext_ as the 5th argument to Block constructor
    Block genesisBlock(1, "0000000000000000000000000000000000000000000000000000000000000000",
                       genesisTransactions, difficulty, rxContext_); // Pasa rxContext_ aquí
    
    // FIX: Call calculateHash() without rxContext_ argument
    genesisBlock.hash = genesisBlock.calculateHash(); // Llama a la función sin argumento
    return genesisBlock;
}

// Obtiene el último bloque de la cadena
const Block& Blockchain::getLatestBlock() const {
    return chain.back();
}

// Obtiene el tamaño actual de la cadena (número de bloques)
size_t Blockchain::getChainSize() const {
    return chain.size();
}

// Añade una transacción a las transacciones pendientes
void Blockchain::addTransaction(const Radix::Transaction& transaction) {
    // Para una blockchain real, aquí se añadirían muchas más validaciones de transacciones.
    // Por ahora, solo verificamos que no sea nula y que sea válida en sí misma.
    // La validación ahora requiere el UTXOSet.
    if (!transaction.isValid(utxoSet)) { // Pasa el UTXOSet para la validación
        throw std::runtime_error("No se puede añadir transaccion invalida a las transacciones pendientes.");
    }
    
    // Una transacción coinbase no debería ser añadida a pendingTransactions
    // directamente a través de addTransaction, ya que se crea durante minePendingTransactions.
    if (transaction.isCoinbase) {
        throw std::runtime_error("No se puede añadir una transaccion coinbase a la lista de transacciones pendientes.");
    }

    pendingTransactions.push_back(transaction);
    std::cout << "Transaccion añadida a pendientes: " << transaction.id << std::endl;
}

// Mina las transacciones pendientes y crea un nuevo bloque
void Blockchain::minePendingTransactions(const std::string& miningRewardAddress) {
    // Si no hay transacciones pendientes, no se mina un bloque (excepto el génesis)
    if (pendingTransactions.empty() && chain.size() > 1) { // Si no es el bloque génesis y no hay transacciones
        std::cout << "No hay transacciones pendientes para minar." << std::endl;
        return;
    }

    // Crear la transacción de recompensa de minería (coinbase)
    Transaction coinbaseTx(miningRewardAddress, miningReward, true); // Es una coinbase

    // Añadirla al principio de las transacciones pendientes para que sea la primera en el bloque.
    std::vector<Transaction> transactionsForBlock = pendingTransactions;
    transactionsForBlock.insert(transactionsForBlock.begin(), coinbaseTx);

    // Crear el nuevo bloque con las transacciones pendientes
    // FIX: Add rxContext_ as the 5th argument to Block constructor
    Block newBlock(getLatestBlock().version + 1, getLatestBlock().hash, transactionsForBlock, difficulty, rxContext_); // Pasa rxContext_ aquí
    
    // Minar el bloque
    // FIX: Call mineBlock() without rxContext_ argument
    newBlock.mineBlock(difficulty); // Llama a la función sin argumento
    
    // Validar el bloque antes de añadirlo a la cadena
    // FIX: Pass utxoSet to isValid()
    if (!newBlock.isValid(utxoSet)) { // Pasa el UTXOSet
        throw std::runtime_error("El bloque minado no es valido y no se puede añadir a la cadena.");
    }

    // Añadir el bloque minado a la cadena
    chain.push_back(newBlock);
    
    // Procesar las transacciones del bloque para actualizar el UTXOSet
    applyBlockTransactionsToUtxoSet(newBlock, utxoSet); // Update the member utxoSet

    // Limpiar las transacciones pendientes
    pendingTransactions.clear();
    std::cout << "Bloque minado y añadido a la cadena. Transacciones pendientes limpiadas." << std::endl;
}

// Obtiene el balance de una dirección específica utilizando el UTXOSet
double Blockchain::getBalanceOfAddress(const std::string& address) const {
    double balance = 0;
    for (const auto& pair : utxoSet) {
        if (pair.second.recipientAddress == address) {
            balance += pair.second.amount;
        }
    }
    return balance;
}

// Nuevo método para obtener las UTXOs de una dirección específica
std::vector<TransactionOutput> Blockchain::getUTXOsForAddress(const std::string& address) const {
    std::vector<TransactionOutput> utxos;
    for (const auto& pair : utxoSet) {
        if (pair.second.recipientAddress == address) {
            utxos.push_back(pair.second);
        }
        // Debugging: Mostrar todas las UTXOs y sus propietarios
        // std::cerr << "DEBUG: UTXO ID: " << pair.first << ", Recipient: " << pair.second.recipientAddress << ", Amount: " << pair.second.amount << std::endl;
    }
    return utxos;
}

// Valida la integridad de toda la cadena
bool Blockchain::isChainValid() const {
    // Iniciar un UTXO set simulado para la validación de la cadena.
    std::map<std::string, TransactionOutput> simulatedUtxoSet;

    // Aplicar las transacciones del bloque génesis al UTXO set simulado
    // El bloque génesis no necesita validación de UTXO de entrada ya que no tiene.
    // Su validez se basa en su estructura interna y el hash.
    const Block& genesisBlock = chain[0];
    if (!genesisBlock.isValid(simulatedUtxoSet)) { // Validar el génesis (no necesita UTXOs previas)
        std::cerr << "Cadena Invalida: El bloque genesis no es valido (fallo en consistencia interna)." << std::endl;
        return false;
    }
    applyBlockTransactionsToUtxoSet(genesisBlock, simulatedUtxoSet); // Aplicar transacciones del génesis

    // Iterar desde el segundo bloque (índice 1) hasta el final
    for (size_t i = 1; i < chain.size(); ++i) {
        const Block& currentBlock = chain[i];
        const Block& previousBlock = chain[i-1];

        // 1. Verificar que el prevHash del bloque actual coincide con el hash del bloque anterior
        if (currentBlock.prevHash != previousBlock.hash) {
            std::cerr << "Cadena Invalida: prevHash del bloque en el indice " << i
                      << " no coincide con el hash del bloque anterior. "
                      << "Esperado: " << previousBlock.hash
                      << ", Encontrado: " << currentBlock.prevHash << std::endl;
            return false;
        }

        // 2. Validar el bloque actual (su propio hash, dificultad y transacciones)
        // Se valida contra el simulatedUtxoSet acumulado hasta este punto.
        if (!currentBlock.isValid(simulatedUtxoSet)) {
            std::cerr << "Cadena Invalida: El bloque en el indice " << i << " no es valido (fallo en hash/dificultad/transacciones)." << std::endl;
            return false;
        }

        // 3. Si el bloque es válido, aplicar sus transacciones al UTXO set simulado para el siguiente bloque
        applyBlockTransactionsToUtxoSet(currentBlock, simulatedUtxoSet);
    }

    return true; // Si todo es válido, la cadena es válida
}

// Imprime todos los bloques en la cadena
void Blockchain::printChain() const {
    for (size_t i = 0; i < chain.size(); ++i) {
        std::cout << "\n--- Bloque #" << i << " ---\n";
        // FIX: Call toString() without rxContext_ argument
        std::cout << chain[i].toString() << std::endl; // Llama a la función sin argumento
    }
}

// Helper para procesar transacciones de un bloque y actualizar un UTXOSet dado.
// Esta función es estática porque no necesita acceder a los miembros de la instancia de Blockchain.
void Blockchain::applyBlockTransactionsToUtxoSet(const Block& block, std::map<std::string, TransactionOutput>& targetUtxoSet) {
    for (const auto& tx : block.transactions) {
        // Eliminar UTXOs gastadas
        if (!tx.isCoinbase) {
            for (const auto& input : tx.inputs) {
                std::string utxoKey = input.prevTxId + ":" + std::to_string(input.outputIndex);
                if (targetUtxoSet.count(utxoKey)) {
                    targetUtxoSet.erase(utxoKey); // Elimina la UTXO gastada
                } else {
                    // Esto no debería pasar si la validación del bloque fue exitosa.
                    // Podría indicar un doble gasto o una UTXO inexistente.
                    std::cerr << "Advertencia: UTXO de entrada no encontrada en UTXOSet durante el procesamiento del bloque: " << utxoKey << std::endl;
                }
            }
        }

        // Añadir nuevas UTXOs (salidas de la transacción)
        for (size_t i = 0; i < tx.outputs.size(); ++i) {
            TransactionOutput newOutput = tx.outputs[i];
            newOutput.utxoId = tx.id + ":" + std::to_string(i); // Genera el UTXO ID
            targetUtxoSet[newOutput.utxoId] = newOutput; // Añade la nueva UTXO
        }
    }
}

} // namespace Radix
