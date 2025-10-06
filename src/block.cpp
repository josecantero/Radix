// block.cpp
#include "block.h"
#include "crypto.h" // Para Radix::SHA256
#include "randomx_util.h" // Para toHexString y RandomXContext
#include "base58.h" // Para Base58::encode y decode (si se usan en otro lugar, la inclusión ya está)
#include "persistence_util.h" // Para serialización binaria

#include <iostream>
#include <sstream>
#include <iomanip> // Para std::hex, std::setfill, std::setw
#include <limits>  // Para std::numeric_limits

namespace Radix {

// --------------------------------------------------------------------------------
// Helper estático para el constructor por defecto (Manejo de Referencia)
// --------------------------------------------------------------------------------
static RandomXContext& get_dummy_rx_context() {
    // Inicialización de la instancia estática única (solo la primera vez)
    // El constructor de RandomXContext debe ser seguro de llamar aquí.
    static RandomXContext dummyContext; 
    return dummyContext;
}

// Constructor vacío para deserialización (¡IMPLEMENTACIÓN REQUERIDA!)
Block::Block()
    : version(0), timestamp(0), prevHash(""), merkleRoot(""), 
      difficulty(0), nonce(0), hash(""), 
      // Inicializa la referencia al contexto dummy estático.
      rxContext_(get_dummy_rx_context()) {
    // Los demás miembros se inicializan con sus constructores por defecto.
}
// --------------------------------------------------------------------------------

// Constructor del bloque
Block::Block(uint64_t version, const std::string& prevHash, const std::vector<Transaction>& transactions,
             unsigned int difficulty, RandomXContext& rxContext_ref)
    : version(version),
      timestamp(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()),
      prevHash(prevHash),
      transactions(transactions),
      difficulty(difficulty),
      nonce(0), // Inicializa el nonce a 0
      rxContext_(rxContext_ref) { // Inicializa la referencia con la referencia real
    // Calcula la raíz de Merkle inmediatamente después de que las transacciones se establecen
    this->merkleRoot = calculateMerkleRoot();
    // El hash inicial se calculará cuando se llame a calculateHash() o mineBlock()
}

// Calcula el hash del bloque usando RandomX
std::string Block::calculateHash() const {
    std::stringstream ss;
    ss << version
       << timestamp
       << prevHash
       << merkleRoot
       << difficulty
       << nonce;

    // ¡CORRECCIÓN 1 AQUÍ! Convertir el RandomXHash a std::string hexadecimal
    return toHexString(rxContext_.hash(ss.str()));
}

// Realiza la Prueba de Trabajo (Proof of Work)
void Block::mineBlock(unsigned int difficulty) {
    std::string target(difficulty, '0'); // Crea una cadena de '0's de la longitud de la dificultad
    std::string currentHash;

    std::cout << "Minando bloque..." << std::endl;

    // Iterar hasta que el hash comience con el número requerido de ceros
    while (true) {
        currentHash = calculateHash();
        if (currentHash.substr(0, difficulty) == target) {
            break; // Se encontró un hash válido
        }
        nonce++; // Incrementa el nonce y prueba de nuevo
        // Pequeño truco para evitar un bucle infinito si el nonce se desborda
        if (nonce == std::numeric_limits<uint64_t>::max()) {
            std::cerr << "Advertencia: Nonce ha alcanzado el maximo. Reiniciando para evitar bucle infinito." << std::endl;
            nonce = 0; 
        }
    }

    hash = currentHash; // Almacena el hash encontrado
    std::cout << "Bloque minado: " << hash << " (Nonce: " << nonce << ")" << std::endl;
}

// Convierte el bloque a una representación de cadena para impresión/depuración
std::string Block::toString() const {
    std::stringstream ss;
    ss << "Version: " << version << "\n"
       << "Timestamp: " << timestamp << "\n"
       << "Previous Hash: " << prevHash << "\n"
       << "Merkle Root: " << merkleRoot << "\n"
       << "Difficulty: " << difficulty << "\n"
       << "Nonce: " << nonce << "\n"
       << "Hash: " << hash << "\n"
       << "Transactions (" << transactions.size() << "):\n";

    for (const auto& tx : transactions) {
        // ¡CORRECCIÓN 2 AQUÍ! Pasa 'true' al método toString de Transaction
        ss << tx.toString(true) << "\n"; // Pasa true para indentar
    }
    return ss.str();
}

// Valida la integridad de un bloque
bool Block::isValid(RandomXContext& rxContext_ref, const std::map<std::string, TransactionOutput>& utxoSet) const {
    // 1. Verificar que el hash del bloque es correcto
    if (this->hash != calculateHash()) {
        std::cerr << "Error de validacion: El hash del bloque no coincide." << std::endl;
        return false;
    }

    // 2. Verificar la raíz de Merkle
    if (this->merkleRoot != calculateMerkleRoot()) {
        std::cerr << "Error de validacion: La raiz de Merkle del bloque no coincide." << std::endl;
        return false;
    }

    // 3. Validar cada transacción dentro del bloque
    std::map<std::string, TransactionOutput> tempUtxoSet = utxoSet; // Copia el UTXO set actual de la cadena

    for (const auto& tx : transactions) {
        if (tx.isCoinbase) {
            if (!tx.inputs.empty()) {
                std::cerr << "Error de validacion: Transaccion coinbase con inputs. TX ID: " << tx.calculateHash() << std::endl;
                return false;
            }
            if (tx.outputs.empty() || tx.outputs[0].amount <= 0) {
                std::cerr << "Error de validacion: Transaccion coinbase invalida (output vacio o monto <= 0). TX ID: " << tx.calculateHash() << std::endl;
                return false;
            }
        } else {
            // Para transacciones regulares, validar contra el tempUtxoSet
            if (!tx.isValid(tempUtxoSet)) {
                std::cerr << "Error de validacion: Transaccion invalida dentro del bloque. TX ID: " << tx.calculateHash() << std::endl;
                return false;
            }

            // Eliminar las UTXOs gastadas (inputs)
            for (const auto& input : tx.inputs) {
                std::string utxoKey = input.prevTxId + ":" + std::to_string(input.outputIndex);
                if (tempUtxoSet.count(utxoKey)) {
                    tempUtxoSet.erase(utxoKey);
                } else {
                    std::cerr << "Error interno de validacion de bloque: UTXO de entrada no encontrada en tempUtxoSet. TX ID: " << tx.calculateHash() << ", UTXO: " << utxoKey << std::endl;
                    return false;
                }
            }
        }

        // Añadir las nuevas UTXOs (outputs) de esta transacción al tempUtxoSet
        for (size_t i = 0; i < tx.outputs.size(); ++i) {
            std::string utxoKey = tx.calculateHash() + ":" + std::to_string(i);
            tempUtxoSet[utxoKey] = tx.outputs[i];
        }
    }

    return true; // Si todas las validaciones pasan
}


// Calcula la raíz de Merkle para las transacciones del bloque
std::string Block::calculateMerkleRoot() const {
    if (transactions.empty()) {
        // ¡CORRECCIÓN 3 AQUÍ! Usar Radix::SHA256 directamente
        return toHexString(Radix::SHA256(""));
    }

    std::vector<std::string> txHashes;
    for (const auto& tx : transactions) {
        txHashes.push_back(tx.calculateHash());
    }

    return buildMerkleTree(txHashes);
}

// Función auxiliar para construir el árbol de Merkle
std::string Block::buildMerkleTree(const std::vector<std::string>& hashes) const {
    if (hashes.empty()) {
        return ""; // Esto no debería pasar si calculateMerkleRoot maneja el caso vacío
    }
    if (hashes.size() == 1) {
        return hashes[0];
    }

    std::vector<std::string> nextLevelHashes;
    for (size_t i = 0; i < hashes.size(); i += 2) {
        std::string left = hashes[i];
        std::string right = (i + 1 < hashes.size()) ? hashes[i+1] : left; // Duplicar el último si es impar
        // ¡CORRECCIÓN 4 AQUÍ! Usar Radix::SHA256 directamente y convertir a hex string
        nextLevelHashes.push_back(toHexString(Radix::SHA256(left + right)));
    }
    return buildMerkleTree(nextLevelHashes);
}

// --------------------------------------------------------------------------------
// Métodos de Persistencia Binaria (Block) - ¡NUEVO!
// --------------------------------------------------------------------------------

void Block::serialize(std::fstream& fs) const {
    Persistence::writePrimitive(fs, version);
    Persistence::writePrimitive(fs, timestamp);
    Persistence::writeString(fs, prevHash);
    Persistence::writeString(fs, merkleRoot);
    Persistence::writePrimitive(fs, difficulty);
    Persistence::writePrimitive(fs, nonce);
    Persistence::writeString(fs, hash);

    // Serializar transacciones
    size_t txCount = transactions.size();
    Persistence::writePrimitive(fs, txCount);
    for (const auto& tx : transactions) {
        tx.serialize(fs); 
    }
}

void Block::deserialize(std::fstream& fs) {
    version = Persistence::readPrimitive<uint64_t>(fs);
    timestamp = Persistence::readPrimitive<long long>(fs);
    prevHash = Persistence::readString(fs);
    merkleRoot = Persistence::readString(fs);
    difficulty = Persistence::readPrimitive<unsigned int>(fs);
    nonce = Persistence::readPrimitive<uint64_t>(fs);
    hash = Persistence::readString(fs);

    // Deserializar transacciones
    size_t txCount = Persistence::readPrimitive<size_t>(fs);
    transactions.resize(txCount);
    for (size_t i = 0; i < txCount; ++i) {
        transactions[i].deserialize(fs); 
    }

    // Nota sobre rxContext_: La referencia fue inicializada a un dummy. 
    // La clase Blockchain debe usar un puntero a Block o una lógica de validación
    // que ignore esta referencia y use el RandomXContext activo de la cadena.
}

} // namespace Radix