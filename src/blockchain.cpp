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
    Block genesisBlock = createGenesisBlock();
    chain.push_back(genesisBlock);
    // El bloque génesis no tiene inputs, solo outputs (si los tiene, como una coinbase inicial, aunque no es lo común)
    // Se aplica el bloque génesis al UTXOSet inicial.
    applyBlockToUTXOSet(genesisBlock, utxoSet);
}

// Crea el bloque génesis (el primer bloque de la cadena)
Block Blockchain::createGenesisBlock() {
    // El bloque génesis no tiene transacciones previas ni prevHash
    // La raíz de Merkle se calculará como el hash de un vector vacío de transacciones inicialmente
    std::vector<Transaction> genesisTransactions;
    // El bloque génesis no tiene una transacción coinbase tradicional.
    // Si quisieras darle un "suministro inicial", podrías añadir una TransactionOutput aquí
    // sin un TransactionInput, pero no sería una coinbase minada.
    // Por ahora, lo dejamos sin transacciones.
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
    if (transaction.isCoinbase) {
        throw std::runtime_error("No se puede añadir una transaccion coinbase a la lista de transacciones pendientes directamente. Se crea durante la mineria.");
    }

    // Validar la transacción preliminarmente contra el UTXOSet actual
    if (!transaction.isValid(utxoSet)) {
        throw std::runtime_error("Transaccion invalida (doble gasto o UTXO inexistente/gastada) o firma incorrecta. No se añade a pendientes.");
    }
    
    // Aquí se podrían añadir más validaciones, como verificar que no haya doble gasto
    // dentro del pool de transacciones pendientes antes de minar. Por ahora, asumimos
    // que isValid() es suficiente para la validación de UTXO.

    pendingTransactions.push_back(transaction);
    std::cout << "Transaccion añadida a pendientes: " << transaction.id << std::endl;
}

// Mina las transacciones pendientes y crea un nuevo bloque
void Blockchain::minePendingTransactions(const std::string& miningRewardAddress) {
    if (pendingTransactions.empty()) {
        std::cout << "No hay transacciones pendientes para minar." << std::endl;
        // Si no hay transacciones pendientes, aún se puede minar un bloque vacío (solo con coinbase).
        // Esto es un diseño de protocolo, algunos permiten bloques vacíos, otros no.
        // Para este ejemplo, permitiremos bloques con solo la coinbase.
    }

    // Crear la transacción de recompensa de minería (coinbase)
    Transaction coinbaseTx(miningRewardAddress, miningReward, true); // Usa el constructor de coinbase
    
    std::vector<Transaction> transactionsForBlock = pendingTransactions;
    transactionsForBlock.insert(transactionsForBlock.begin(), coinbaseTx); // La coinbase siempre es la primera

    // Crear el nuevo bloque con las transacciones pendientes
    Block newBlock(getLatestBlock().version + 1, getLatestBlock().hash, transactionsForBlock, difficulty, rxContext_);
    
    // Minar el bloque
    newBlock.mineBlock(difficulty);

    // Antes de añadir el bloque, validarlo contra el UTXOSet actual
    // Esto es crucial para asegurar que el bloque minado no contiene transacciones inválidas
    // que podrían haber sido añadidas al pool antes de que se gastaran sus UTXO.
    // Para la validación final, es mejor crear una copia temporal del UTXOSet
    // y aplicar el bloque a esa copia. Si la validación falla, no se añade el bloque.
    UTXOSet tempUtxoSet = utxoSet; // Crea una copia del UTXOSet actual
    if (!newBlock.isValid(tempUtxoSet)) { // Pasa la copia para la validación del bloque
        std::cerr << "Error: El bloque minado es invalido. No se añadira a la cadena." << std::endl;
        // Las transacciones pendientes que eran válidas pero no se minaron
        // debido a un bloque inválido, permanecerán en pendingTransactions.
        return;
    }

    // Si el bloque es válido, aplicar sus transacciones al UTXOSet principal
    // (esto ya se hizo en la validación, pero se debe confirmar la actualización)
    // La función applyBlockToUTXOSet se encarga de esto.
    if (!applyBlockToUTXOSet(newBlock, utxoSet)) {
        std::cerr << "Error critico: Fallo al aplicar el bloque valido al UTXOSet. Posible inconsistencia." << std::endl;
        return;
    }

    // Añadir el bloque minado a la cadena
    chain.push_back(newBlock);

    // Limpiar las transacciones pendientes que fueron incluidas en el bloque
    pendingTransactions.clear(); // Se asume que todas las transacciones pendientes fueron incluidas
    std::cout << "Bloque minado y añadido a la cadena. Transacciones pendientes limpiadas." << std::endl;
}

// Aplica las transacciones de un bloque al UTXOSet.
// Esto implica eliminar las UTXO gastadas y añadir las nuevas UTXO creadas.
bool Blockchain::applyBlockToUTXOSet(const Block& block, UTXOSet& currentUtxoSet) const {
    for (const auto& tx : block.transactions) {
        if (!tx.isCoinbase) { // Las transacciones coinbase no gastan UTXO
            // Eliminar UTXO gastadas
            for (const auto& input : tx.inputs) {
                std::string utxoKey = input.prevTxId + ":" + std::to_string(input.outputIndex);
                if (currentUtxoSet.count(utxoKey) == 0) {
                    // Esto no debería suceder si el bloque ya fue validado,
                    // pero es una salvaguarda.
                    std::cerr << "Error al aplicar bloque al UTXOSet: UTXO gastada ya no existe: " << utxoKey << std::endl;
                    return false; // Indica un fallo crítico al aplicar el bloque
                }
                currentUtxoSet.erase(utxoKey);
            }
        }

        // Añadir nuevas UTXO (outputs de la transacción)
        for (const auto& output : tx.outputs) {
            // El utxoId ya debería estar establecido en la transacción.
            // Si no lo está, se puede generar aquí: tx.id + ":" + std::to_string(output_index)
            // Asegurarse de que el utxoId en TransactionOutput se haya actualizado correctamente.
            currentUtxoSet[output.utxoId] = output;
        }
    }
    return true;
}


// Obtiene el balance de una dirección específica utilizando el UTXOSet.
double Blockchain::getBalanceOfAddress(const std::string& address) const {
    double balance = 0;
    for (const auto& pair : utxoSet) {
        const TransactionOutput& utxo = pair.second;
        if (utxo.recipientAddress == address) {
            balance += utxo.amount;
        }
    }
    return balance;
}

// Valida la integridad de toda la cadena, reconstruyendo el UTXOSet en el proceso.
bool Blockchain::isChainValid() const {
    // Crear un UTXOSet temporal para reconstruir el estado durante la validación
    UTXOSet tempUtxoSet;

    // El bloque génesis (índice 0) tiene un tratamiento especial para su validez.
    // Se valida su integridad interna y se aplica al UTXOSet.
    if (!chain[0].isValid(tempUtxoSet)) { // Pasa el UTXOSet vacío para el génesis
        std::cerr << "Cadena Invalida: El bloque genesis no es valido (fallo en consistencia interna)." << std::endl;
        return false;
    }
    // Aplicar el bloque génesis al UTXOSet temporal
    if (!applyBlockToUTXOSet(chain[0], tempUtxoSet)) {
        std::cerr << "Cadena Invalida: Fallo al aplicar el bloque genesis al UTXOSet." << std::endl;
        return false;
    }


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

        // 2. Validar el bloque actual contra el UTXOSet *actual* (antes de aplicar este bloque)
        // Esto asegura que las transacciones en currentBlock son válidas con los fondos disponibles hasta previousBlock.
        if (!currentBlock.isValid(tempUtxoSet)) { // Pasa el UTXOSet acumulado hasta el bloque anterior
            std::cerr << "Cadena Invalida: El bloque en el indice " << i << " no es valido (fallo en hash/dificultad/transacciones/UTXO)." << std::endl;
            return false;
        }

        // 3. Aplicar las transacciones de este bloque al UTXOSet temporal para el siguiente bloque
        if (!applyBlockToUTXOSet(currentBlock, tempUtxoSet)) {
            std::cerr << "Cadena Invalida: Fallo al aplicar el bloque " << i << " al UTXOSet." << std::endl;
            return false;
        }
    }

    return true; // Si todo es válido, la cadena es válida
}

// Imprime todos los bloques en la cadena
void Blockchain::printChain() const {
    for (size_t i = 0; i < chain.size(); ++i) {
        std::cout << "\n--- Bloque #" << i << " ---\n";
        std::cout << chain[i].toString() << std::endl;
    }
}

} // namespace Radix
