// blockchain.cpp
#include "blockchain.h"
#include "block.h"
#include "transaction.h"
#include "crypto.h" // Para SHA256
#include "randomx_util.h" // Para RandomXContext
#include "persistence_util.h" // Para serialización binaria
#include "money_util.h" // Se asume que existe para formatRadsToRDX

#include <iostream>
#include <fstream>      // Para gestión de archivos
#include <stdexcept>    // Para std::runtime_error
#include <algorithm>    // Para std::remove_if
#include <utility>      // Para std::pair

namespace Radix {

// Constante para el factor de decimales de la moneda (10^8)
//const uint64_t RDX_DECIMAL_FACTOR = 100000000ULL; // 10^8

// Constructor de la Blockchain
Blockchain::Blockchain(unsigned int difficulty, Radix::RandomXContext& rxContext_ref)
    : difficulty(difficulty), currentMiningReward(100ULL * RDX_DECIMAL_FACTOR), rxContext_(rxContext_ref) { // Recompensa de minería inicial y referencia
    // El constructor por defecto ahora solo inicializa, si se llama a loadChain
    // no se creará el bloque génesis. Si no se llama, el código externo
    // debe verificar si la cadena está vacía y llamar a createGenesisBlock/minePendingTransactions
    // o el código de inicialización que sigue aquí:

    // NOTA IMPORTANTE: Para la inicialización del constructor, asumimos que si se crea una instancia
    // nueva, debe tener un bloque génesis.

    if (chain.empty()) {
        // Crea el bloque génesis y lo añade a la cadena
        chain.push_back(createGenesisBlock());
        // Inicializa el UTXO Set con las salidas del bloque génesis
        updateUtxoSet(chain[0]);
        std::cout << "Blockchain inicializada con bloque genesis y dificultad: " << difficulty << std::endl;
    }
}

// Crea el bloque génesis
Block Blockchain::createGenesisBlock() {
    // La transacción coinbase del bloque génesis.
    Transaction genesisCoinbase("genesis_miner_address", currentMiningReward, true);

    std::vector<Transaction> genesisTransactions;
    genesisTransactions.push_back(genesisCoinbase);

    // Crear el bloque génesis
    Block genesisBlock(1, "0000000000000000000000000000000000000000000000000000000000000000",
                       genesisTransactions, difficulty, rxContext_);

    // Calcular y asignar el hash del bloque génesis
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
void Blockchain::minePendingTransactions(const std::string& miningRewardAddress, const std::atomic<bool>& running) {
    // Lógica del Halving:
    if (chain.size() > 0 && chain.size() % HALVING_INTERVAL == 0) {
        currentMiningReward /= 2;
        std::cout << "\n¡HALVING! La recompensa de mineria se ha reducido a: " << Radix::formatRadsToRDX(currentMiningReward) << " RDX\n";
    }

    // Crear la transacción de recompensa de minería (coinbase)
    Transaction miningRewardTx(miningRewardAddress, currentMiningReward, true);
    // Añadirla al principio de las transacciones pendientes para que sea la primera en el bloque.
    std::vector<Transaction> transactionsForBlock = pendingTransactions;
    transactionsForBlock.insert(transactionsForBlock.begin(), miningRewardTx);


    // Crear un nuevo bloque
    std::string previousHash = getLatestBlock().hash;
    Block newBlock(getLatestBlock().version + 1, previousHash, transactionsForBlock, difficulty, rxContext_);

    // Minar el bloque (encontrar un nonce válido)
    std::cout << "Iniciando mineria del bloque con " << transactionsForBlock.size() << " transacciones..." << std::endl;
    newBlock.mineBlock(difficulty, running);
    
    if (!running) return; // Si se detuvo la minería, salir sin añadir el bloque

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

        // 1. Validaciones de enlace de la cadena
        if (i > 0) {
            const Block& previousBlock = chain[i - 1];
            if (currentBlock.prevHash != previousBlock.hash) {
                std::cerr << "Cadena Invalida: prevHash del bloque en el indice " << i
                          << " no coincide con el hash del bloque anterior." << std::endl;
                return false;
            }
        } else { // Bloque Génesis
            if (currentBlock.prevHash != "0000000000000000000000000000000000000000000000000000000000000000") {
                std::cerr << "Bloque Genesis invalido: prevHash incorrecto." << std::endl;
                return false;
            }
        }
        
        // 2. Validar el bloque completo, incluyendo sus transacciones.
        if (!currentBlock.isValid(rxContext_, tempUtxoSet)) {
            std::cerr << "Cadena Invalida: El bloque en el indice " << i << " no es valido (fallo en hash/dificultad/transacciones)." << std::endl;
            return false;
        }
        
        // 3. Simular la actualización del UTXO Set para el siguiente bloque.
        for (const auto& tx : currentBlock.transactions) {
            // Eliminar UTXOs gastadas (inputs)
            if (!tx.isCoinbase) {
                for (const auto& input : tx.inputs) {
                    std::string utxoKey = input.prevTxId + ":" + std::to_string(input.outputIndex);
                    // Ya fue validado en Block::isValid, solo necesitamos actualizar el estado.
                    tempUtxoSet.erase(utxoKey); 
                }
            }
            // Añadir nuevas UTXOs (outputs)
            for (size_t k = 0; k < tx.outputs.size(); ++k) {
                std::string utxoKey = tx.id + ":" + std::to_string(k);
                tempUtxoSet[utxoKey] = tx.outputs[k];
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

// Obtiene la altura de un bloque dado su hash. Retorna -1 si no se encuentra.
int Blockchain::getBlockHeight(const std::string& hash) const {
    for (size_t i = 0; i < chain.size(); ++i) {
        if (chain[i].hash == hash) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

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
            std::string utxoKey = tx.id + ":" + std::to_string(i); 
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
    std::cout << "UTXO Set reconstruido con " << utxoSet.size() << " entradas.\n";
}

// --------------------------------------------------------------------------------
// MÉTODOS DE PERSISTENCIA BINARIA (BLOCKCHAIN) - ¡IMPLEMENTACIÓN!
// --------------------------------------------------------------------------------

void Blockchain::saveChain(const std::string& filename) const {
    std::fstream fs(filename, std::ios::out | std::ios::binary);
    if (!fs.is_open()) {
        throw std::runtime_error("No se pudo abrir el archivo para guardar la cadena: " + filename);
    }

    // 1. Guardar primitivos
    Persistence::writePrimitive(fs, difficulty);
    Persistence::writePrimitive(fs, currentMiningReward);

    // 2. Guardar la cadena de bloques (vector<Block>)
    size_t chainSize = chain.size();
    Persistence::writePrimitive(fs, chainSize);
    for (const auto& block : chain) {
        block.serialize(fs);
    }

    // 3. Guardar transacciones pendientes (vector<Transaction>)
    size_t pendingTxSize = pendingTransactions.size();
    Persistence::writePrimitive(fs, pendingTxSize);
    for (const auto& tx : pendingTransactions) {
        tx.serialize(fs);
    }

    // 4. Guardar UTXO Set (map<string, TransactionOutput>)
    size_t utxoSetSize = utxoSet.size();
    Persistence::writePrimitive(fs, utxoSetSize);
    for (const auto& pair : utxoSet) {
        Persistence::writeString(fs, pair.first); // La clave (txId:outputIndex)
        pair.second.serialize(fs);                // El valor (TransactionOutput)
    }

    fs.close();
    std::cout << "Blockchain guardada exitosamente en: " << filename << std::endl;
}

bool Blockchain::loadChain(const std::string& filename) {
    std::fstream fs(filename, std::ios::in | std::ios::binary);
    if (!fs.is_open()) {
        std::cerr << "Advertencia: No se pudo abrir el archivo de cadena (" << filename << "), se asumira una nueva inicializacion." << std::endl;
        return false;
    }

    try {
        // 1. Cargar primitivos
        difficulty = Persistence::readPrimitive<unsigned int>(fs);
        currentMiningReward = Persistence::readPrimitive<uint64_t>(fs);

        // 2. Cargar la cadena de bloques (vector<Block>)
        size_t chainSize = Persistence::readPrimitive<size_t>(fs);
        chain.resize(chainSize);
        for (size_t i = 0; i < chainSize; ++i) {
            // Nota: Block::deserialize establece la referencia rxContext_ al dummy estático.
            // Esto es seguro ya que rxContext_ no se usará hasta que se llame a isChainValid/minePendingTransactions
            chain[i].deserialize(fs); 
        }

        // 3. Cargar transacciones pendientes (vector<Transaction>)
        size_t pendingTxSize = Persistence::readPrimitive<size_t>(fs);
        pendingTransactions.resize(pendingTxSize);
        for (size_t i = 0; i < pendingTxSize; ++i) {
            pendingTransactions[i].deserialize(fs);
        }

        // 4. Cargar UTXO Set (map<string, TransactionOutput>) - OPCIONAL: reconstruir es más seguro
        // Aquí optamos por reconstruir el UTXO set después de la validación para máxima seguridad.
        // Solo necesitamos limpiar el UTXO set cargado y confiar en rebuildUtxoSet().
        size_t utxoSetSize = Persistence::readPrimitive<size_t>(fs);
        utxoSet.clear(); 
        for (size_t i = 0; i < utxoSetSize; ++i) {
            std::string key = Persistence::readString(fs);
            TransactionOutput output;
            output.deserialize(fs);
            // Ignoramos el resultado y dejamos que rebuildUtxoSet() haga el trabajo de verdad.
        }

        fs.close();

        // CRÍTICO: 5. Reconstruir el UTXO Set y validar la integridad de la cadena.
        rebuildUtxoSet(); // Reconstruir el UTXO Set a partir de la cadena cargada
        if (!isChainValid()) {
            // Si la cadena es inválida, se descarta y se reinicializa.
            std::cerr << "Error: La cadena cargada del archivo es INVALIDA. Se descartara el estado cargado." << std::endl;
            // Para "descartar el estado", simplemente se puede vaciar la cadena y dejar que el constructor/código externo
            // cree un nuevo génesis. Aquí solo retornamos false.
            chain.clear();
            pendingTransactions.clear();
            utxoSet.clear();
            return false;
        }

        std::cout << "Blockchain cargada exitosamente desde: " << filename << ". Tamanio: " << chain.size() << " bloques." << std::endl;
        return true;

    } catch (const std::exception& e) {
        std::cerr << "Error critico durante la carga binaria de la Blockchain. Se descarta el estado: " << e.what() << std::endl;
        fs.close();
        chain.clear();
        pendingTransactions.clear();
        utxoSet.clear();
        return false;
    }
}

// Obtiene el hash del bloque en una altura específica
std::string Blockchain::getBlockHash(uint64_t index) const {
    if (index < chain.size()) {
        return chain[index].hash;
    }
    return "";
}

Blockchain::BlockStatus Blockchain::submitBlock(const Block& block) {
    // 1. Check if we already have this block
    for (const auto& b : chain) {
        if (b.hash == block.hash) {
            return BlockStatus::IGNORED_DUPLICATE;
        }
    }

    // 2. Check if it extends the tip
    if (block.prevHash == getLatestBlock().hash) {
        // Validate block
        std::map<std::string, TransactionOutput> tempUtxo = utxoSet;
        if (block.isValid(rxContext_, tempUtxo)) { 
             chain.push_back(block);
             updateUtxoSet(block);
             return BlockStatus::ACCEPTED;
        } else {
             return BlockStatus::REJECTED_INVALID;
        }
    }

    // 3. Check for Fork / Reorg (Simplified detection)
    // Find the ancestor
    int ancestorIndex = -1;
    for (int i = chain.size() - 1; i >= 0; --i) {
        if (chain[i].hash == block.prevHash) {
            ancestorIndex = i;
            break;
        }
    }

    if (ancestorIndex != -1) {
        size_t depth = chain.size() - 1 - ancestorIndex;
        const size_t SAFE_DEPTH = 5; 

        if (depth > SAFE_DEPTH) {
            return BlockStatus::REQUIRES_WITNESSING;
        }
        return BlockStatus::FORK_DETECTED;
    }

    return BlockStatus::REJECTED_INVALID;
}

} // namespace Radix