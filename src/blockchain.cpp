// blockchain.cpp
#include "blockchain.h"
#include "block.h"
#include "transaction.h"
#include "crypto.h" // Para SHA256
#include "randomx_util.h" // Para RandomXContext
#include <iostream>
#include <stdexcept> // Para std::runtime_error
#include <algorithm> // Para std::remove_if

namespace Radix {

// Constante para el intervalo de halving (cada cuantos bloques la recompensa se reduce a la mitad)
// Esta constante debe estar definida SOLO en blockchain.h
// const unsigned int HALVING_INTERVAL = 2; // Ejemplo: cada 2 bloques (ELIMINAR ESTA LÍNEA SI EXISTE AQUÍ)

const uint64_t RDX_DECIMAL_FACTOR = 100000000ULL; // 10^8
// Constructor de la Blockchain
Blockchain::Blockchain(unsigned int difficulty, Radix::RandomXContext& rxContext_ref)
    : difficulty(difficulty), currentMiningReward(100ULL * RDX_DECIMAL_FACTOR), rxContext_(rxContext_ref) { // Recompensa de minería inicial y referencia
    // Crea el bloque génesis y lo añade a la cadena
    chain.push_back(createGenesisBlock());
    // Inicializa el UTXO Set con las salidas del bloque génesis
    updateUtxoSet(chain[0]);
    std::cout << "Blockchain inicializada con dificultad: " << difficulty << std::endl;
}

// Crea el bloque génesis
Block Blockchain::createGenesisBlock() {
    // La transacción coinbase del bloque génesis.
    // En el génesis, la recompensa inicial va a una dirección ficticia o a la primera dirección conocida.
    Transaction genesisCoinbase("genesis_miner_address", currentMiningReward, true);

    std::vector<Transaction> genesisTransactions;
    genesisTransactions.push_back(genesisCoinbase);

    // Crear el bloque génesis
    Block genesisBlock(1, "0000000000000000000000000000000000000000000000000000000000000000",
                       genesisTransactions, difficulty, rxContext_);

    // ¡CORRECCIÓN CLAVE AQUÍ! Calcular y asignar el hash del bloque génesis
    genesisBlock.hash = genesisBlock.calculateHash();

    return genesisBlock;
}

// Añade una transacción a las transacciones pendientes
void Blockchain::addTransaction(const Radix::Transaction& transaction) {
    // Validar la transacción antes de añadirla a la piscina
    if (!transaction.isValid(utxoSet)) {
        throw std::runtime_error("Transaccion invalida. No se puede anadir a la piscina de transacciones pendientes.");
    }
    pendingTransactions.push_back(transaction);
    std::cout << "Transaccion " << transaction.id << " anadida a la piscina de pendientes." << std::endl;
}

// Mina las transacciones pendientes y crea un nuevo bloque
void Blockchain::minePendingTransactions(const std::string& miningRewardAddress) {
    // Lógica del Halving:
    // La recompensa se reduce a la mitad si el número de bloques minados (sin contar el actual)
    // es un múltiplo del HALVING_INTERVAL.
    // El bloque génesis tiene índice 0, el primer bloque minado es índice 1, etc.
    // Por lo tanto, el primer halving ocurre cuando el tamaño de la cadena es HALVING_INTERVAL.
    if (chain.size() > 0 && chain.size() % HALVING_INTERVAL == 0) {
        currentMiningReward /= 2;
        std::cout << "\n¡HALVING! La recompensa de mineria se ha reducido a: " << currentMiningReward << " RDX\n";
    }

    // Crear la transacción de recompensa de minería (coinbase)
    Transaction miningRewardTx(miningRewardAddress, currentMiningReward, true);
    // Añadirla al principio de las transacciones pendientes para que sea la primera en el bloque.
    std::vector<Transaction> transactionsForBlock = pendingTransactions;
    transactionsForBlock.insert(transactionsForBlock.begin(), miningRewardTx);


    // Crear un nuevo bloque con las transacciones pendientes
    // El hash del bloque anterior es el hash del último bloque en la cadena
    std::string previousHash = getLatestBlock().hash;
    Block newBlock(getLatestBlock().version + 1, previousHash, transactionsForBlock, difficulty, rxContext_);

    // Minar el bloque (encontrar un nonce válido)
    std::cout << "Iniciando mineria del bloque con " << transactionsForBlock.size() << " transacciones..." << std::endl;
    newBlock.mineBlock(difficulty);
    std::cout << "Bloque minado! Hash: " << newBlock.hash << ", Nonce: " << newBlock.nonce << std::endl;

    // Añadir el nuevo bloque a la cadena
    chain.push_back(newBlock);

    // Actualizar el UTXO Set con las transacciones del nuevo bloque
    updateUtxoSet(newBlock);

    // Limpiar las transacciones pendientes (ya están en el nuevo bloque)
    pendingTransactions.clear();
}

// Obtiene el balance de una dirección específica utilizando el UTXOSet
uint64_t Blockchain::getBalanceOfAddress(const std::string& address) const {
    uint64_t balance = 0;
    for (const auto& pair : utxoSet) {
        const TransactionOutput& utxo = pair.second;
        if (utxo.recipientAddress == address) {
            balance += utxo.amount;
        }
    }
    return balance;
}

// Valida la integridad de toda la cadena
bool Blockchain::isChainValid() const {
    // Creamos un UTXO Set temporal para la validación incremental.
    std::map<std::string, TransactionOutput> tempUtxoSet;

    // Iterar desde el bloque génesis (índice 0) hasta el final.
    for (size_t i = 0; i < chain.size(); ++i) {
        const Block& currentBlock = chain[i];

        // Para el bloque génesis (i == 0), verificar su hash y prevHash especial
        if (i == 0) {
            // CORRECCIÓN: Usar prevHash, no previousHash
            if (currentBlock.prevHash != "0000000000000000000000000000000000000000000000000000000000000000") {
                std::cerr << "Bloque Genesis invalido: prevHash incorrecto." << std::endl;
                return false;
            }
            // CORRECCIÓN: calculateHash() no toma RandomXContext como argumento
            if (currentBlock.calculateHash() != currentBlock.hash) {
                std::cerr << "Bloque Genesis invalido: Hash incorrecto." << std::endl;
                return false;
            }
        } else { // Para todos los bloques excepto el génesis
            const Block& previousBlock = chain[i - 1];

            // 1. Verificar si el previousHash apunta al hash del bloque anterior
            // CORRECCIÓN: Usar prevHash, no previousHash
            if (currentBlock.prevHash != previousBlock.hash) {
                std::cerr << "Cadena Invalida: prevHash del bloque en el indice " << i
                          << " no coincide con el hash del bloque anterior. "
                          << "Esperado: " << previousBlock.hash
                          << ", Encontrado: " << currentBlock.prevHash << std::endl;
                return false;
            }

            // 2. Verificar la prueba de trabajo (Proof of Work)
            // CORRECCIÓN: calculateHash() no toma RandomXContext como argumento
            std::string calculatedBlockHash = currentBlock.calculateHash();
            std::string target(currentBlock.difficulty, '0');
            if (calculatedBlockHash.substr(0, currentBlock.difficulty) != target) {
                std::cerr << "Cadena Invalida: El hash del bloque en el indice " << i
                          << " no cumple con la dificultad requerida. Hash: " << calculatedBlockHash << std::endl;
                return false;
            }
        }
        
        // 3. Validar el bloque completo, incluyendo sus transacciones, usando el tempUtxoSet.
        // La validación de Merkle Root se hace dentro de Block::isValid()
        if (!currentBlock.isValid(rxContext_, tempUtxoSet)) {
            std::cerr << "Cadena Invalida: El bloque en el indice " << i << " no es valido (fallo en hash/dificultad/transacciones)." << std::endl;
            return false;
        }
        
        // Después de validar el bloque y sus transacciones (usando el tempUtxoSet *antes* de este bloque),
        // actualizamos el tempUtxoSet *con las transacciones de este bloque* para el siguiente bloque.
        for (const auto& tx : currentBlock.transactions) {
            // Si no es una transacción coinbase, sus inputs gastan UTXOs existentes
            if (!tx.isCoinbase) {
                for (const auto& input : tx.inputs) {
                    std::string utxoKey = input.prevTxId + ":" + std::to_string(input.outputIndex);
                    if (tempUtxoSet.count(utxoKey)) {
                        tempUtxoSet.erase(utxoKey);
                    } else {
                        std::cerr << "Error interno de validacion: UTXO gastado no encontrado en tempUtxoSet durante la reconstruccion. Bloque " << i << ", TX: " << tx.id << ", UTXO: " << utxoKey << std::endl;
                        return false;
                    }
                }
            }
            // Todas las transacciones (coinbase y estándar) crean nuevas UTXOs (sus outputs)
            for (size_t k = 0; k < tx.outputs.size(); ++k) {
                std::string utxoKey = tx.id + ":" + std::to_string(k);
                tempUtxoSet[utxoKey] = tx.outputs[k]; // Añadir la nueva UTXO
            }
        }
    }

    return true; // Si todo es válido, la cadena es válida
}

// Imprime todos los bloques en la cadena
void Blockchain::printChain() const {
    std::cout << "--- Cadena de Bloques Radix ---\n";
    for (size_t i = 0; i < chain.size(); ++i) {
        std::cout << "\nBloque #" << i << ":\n";
        std::cout << chain[i].toString() << "\n";
    }
    std::cout << "------------------------------\n";
}

// Obtiene el último bloque de la cadena
const Block& Blockchain::getLatestBlock() const {
    return chain.back();
}

// Obtiene el tamaño actual de la cadena (número de bloques)
size_t Blockchain::getChainSize() const {
    return chain.size();
}

// Implementación de getUtxoSet() - Ya está definida inline en blockchain.h

// Actualiza el UTXOSet con las transacciones de un nuevo bloque
void Blockchain::updateUtxoSet(const Block& block) {
    for (const auto& tx : block.transactions) {
        // Si no es una transacción coinbase, sus inputs gastan UTXOs existentes
        if (!tx.isCoinbase) {
            for (const auto& input : tx.inputs) {
                std::string utxoKey = input.prevTxId + ":" + std::to_string(input.outputIndex);
                utxoSet.erase(utxoKey); // Eliminar la UTXO gastada
            }
        }
        // Todas las transacciones (coinbase y estándar) crean nuevas UTXOs (sus outputs)
        for (size_t i = 0; i < tx.outputs.size(); ++i) {
            std::string utxoKey = tx.id + ":" + std::to_string(i); // Usar tx.id, no tx.calculateHash()
            utxoSet[utxoKey] = tx.outputs[i]; // Añadir la nueva UTXO
        }
    }
}

// Reinicia el UTXOSet y lo reconstruye a partir de la cadena actual
void Blockchain::rebuildUtxoSet() {
    utxoSet.clear(); // Limpiar el UTXO Set actual
    for (const auto& block : chain) {
        updateUtxoSet(block); // Reconstruir el UTXO Set bloque por bloque
    }
}

} // namespace Radix
