// block.cpp
#include "block.h"
#include "crypto.h" // Para Radix::SHA256
#include "randomx_util.h" // Para toHexString y RandomXContext
#include "base58.h" // Para Base58::encode y decode (si se usan en otro lugar, la inclusión ya está)

#include <iostream>
#include <sstream>
#include <iomanip> // Para std::hex, std::setfill, std::setw
#include <limits>  // Para std::numeric_limits

namespace Radix {

// Constructor del bloque
Block::Block(uint64_t version, const std::string& prevHash, const std::vector<Transaction>& transactions,
             unsigned int difficulty, RandomXContext& rxContext_ref)
    : version(version),
      timestamp(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()),
      prevHash(prevHash),
      transactions(transactions),
      difficulty(difficulty),
      nonce(0), // Inicializa el nonce a 0
      rxContext_(rxContext_ref) { // Inicializa la referencia
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
            nonce = 0; // Reiniciar nonce y quizás ajustar el timestamp o transacciones si esto ocurre en un escenario real
            // En una blockchain real, esto indicaría un problema grave o una dificultad inalcanzable.
            // Para esta demostración, simplemente reiniciamos y continuamos.
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

    // 2. Verificar que el hash cumple con la dificultad (si no es el bloque génesis)
    // La verificación de dificultad para el bloque génesis se maneja en Blockchain::isChainValid
    // Aquí, solo verificamos que el hash calculado coincida con el hash almacenado.
    // La lógica de dificultad se aplica en mineBlock y se verifica en Blockchain::isChainValid.

    // 3. Verificar la raíz de Merkle
    if (this->merkleRoot != calculateMerkleRoot()) {
        std::cerr << "Error de validacion: La raiz de Merkle del bloque no coincide." << std::endl;
        return false;
    }

    // 4. Validar cada transacción dentro del bloque
    // Usamos un UTXO set temporal que se va actualizando a medida que procesamos las transacciones
    // dentro de este bloque, para simular el gasto de UTXOs.
    std::map<std::string, TransactionOutput> tempUtxoSet = utxoSet; // Copia el UTXO set actual de la cadena

    for (const auto& tx : transactions) {
        // Para transacciones coinbase, solo verificar que el output sea válido (no negativo, etc.)
        // y que no tengan inputs.
        if (tx.isCoinbase) {
            if (!tx.inputs.empty()) {
                std::cerr << "Error de validacion: Transaccion coinbase con inputs. TX ID: " << tx.calculateHash() << std::endl;
                return false;
            }
            if (tx.outputs.empty() || tx.outputs[0].amount <= 0) {
                std::cerr << "Error de validacion: Transaccion coinbase invalida (output vacio o monto <= 0). TX ID: " << tx.calculateHash() << std::endl;
                return false;
            }
            // Las transacciones coinbase no gastan UTXOs, solo crean.
        } else {
            // Para transacciones regulares, validar contra el tempUtxoSet
            if (!tx.isValid(tempUtxoSet)) {
                std::cerr << "Error de validacion: Transaccion invalida dentro del bloque. TX ID: " << tx.calculateHash() << std::endl;
                return false;
            }

            // Si la transacción es válida, actualizar el tempUtxoSet para las siguientes transacciones en el bloque
            // Eliminar las UTXOs gastadas (inputs)
            for (const auto& input : tx.inputs) {
                std::string utxoKey = input.prevTxId + ":" + std::to_string(input.outputIndex);
                if (tempUtxoSet.count(utxoKey)) {
                    tempUtxoSet.erase(utxoKey);
                } else {
                    // Esto no debería pasar si tx.isValid ya verificó la existencia
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

} // namespace Radix
