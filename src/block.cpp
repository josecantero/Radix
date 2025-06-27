// block.cpp
#include "block.h"
#include "randomx_util.h" // Para RandomX functions, toHexString, fromHexString
#include "crypto.h" // Para Radix::SHA256
#include "transaction.h" // Asegura que la clase Transaction esté disponible

#include <iostream>
#include <sstream>
#include <chrono>
#include <algorithm> // Para std::all_of

namespace Radix {

// Constructor del bloque
Block::Block(int version, std::string prevHash, std::vector<Transaction> transactions,
             unsigned int difficultyTarget, const RandomXContext& rxContext_ref)
    : version(version), prevHash(prevHash), transactions(transactions),
      difficultyTarget(difficultyTarget), nonce(0), rxContext_(rxContext_ref) { // Inicializa rxContext_
    this->timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch()).count();
    updateMerkleRoot(); // Calcula la raíz de Merkle inicial
    this->hash = calculateHash(); // Hash inicial del bloque, se recalculará durante la minería
}

// Calcula el hash del encabezado del bloque utilizando el algoritmo RandomX.
// Ya no necesita el rxContext como parámetro, usa la referencia miembro.
std::string Block::calculateHash() const {
    std::stringstream ss;
    ss << version << prevHash << merkleRoot << timestamp << difficultyTarget << nonce;
    std::string header_data = ss.str();

    // Usa RandomX para calcular el hash del bloque
    Radix::RandomXHash rx_hash = rxContext_.hash(header_data); // Usa rxContext_
    return Radix::toHexString(rx_hash);
}

// Mina el bloque: encuentra un 'nonce' tal que el hash del bloque cumpla con la dificultad.
// Ya no necesita el rxContext como parámetro, usa la referencia miembro.
void Block::mineBlock(unsigned int difficulty) {
    // Mensaje inicial, el nonce se actualizará en el bucle
    std::cout << "Minando bloque (dificultad: " << difficulty << ")..." << std::endl;
    long long attempts = 0; // Contador de intentos de minería
    while (true) {
        this->hash = calculateHash(); // Recalcula el hash con el nonce actual
        attempts++; // Incrementa el contador de intentos

        // Mensaje de depuración para ver cada intento de minería
        if (attempts % 100000 == 0 || attempts == 1) { // Imprime cada 100,000 intentos o el primero
            std::cout << "  Intento #" << attempts << ", Nonce: " << nonce << ", Hash: " << hash << std::endl;
        }

        if (checkDifficulty(difficulty)) { // Comprueba si el hash cumple la dificultad
            std::cout << "Bloque minado exitosamente con Nonce: " << nonce << " (en " << attempts << " intentos)." << std::endl;
            break; // Si cumple, se encontró el nonce, salimos del bucle
        }
        nonce++; // Incrementa el nonce y reintenta
        this->timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch()).count(); // Actualiza la marca de tiempo en cada intento
    }
}

// Actualiza la raíz de Merkle del bloque. La raíz de Merkle es un hash de todos los hashes de transacción.
void Block::updateMerkleRoot() {
    if (transactions.empty()) {
        // Si no hay transacciones, la Raíz de Merkle puede ser el hash de una cadena vacía o un valor fijo.
        // Por simplicidad, se hash de una cadena vacía.
        Radix::RandomXHash empty_hash = Radix::SHA256(""); // Se asume SHA256 de string a RandomXHash
        merkleRoot = Radix::toHexString(empty_hash);
        return;
    }

    std::vector<std::string> current_hashes_str;
    // Obtiene el hash de cada transacción para iniciar el árbol de Merkle.
    for (const auto& tx : transactions) {
        current_hashes_str.push_back(tx.calculateHash());
    }

    // Construye el árbol de Merkle, combinando pares de hashes hasta que solo quede uno (la raíz).
    while (current_hashes_str.size() > 1) {
        std::vector<std::string> next_hashes_str;
        // Si hay un número impar de nodos, duplica el último
        if (current_hashes_str.size() % 2 != 0) {
            current_hashes_str.push_back(current_hashes_str.back());
        }

        for (size_t i = 0; i < current_hashes_str.size(); i += 2) {
            std::string combined_hash_str = current_hashes_str[i] + current_hashes_str[i+1];
            // Hash la combinación usando Radix::SHA256 (que usa SHA256 de OpenSSL)
            Radix::RandomXHash combined_hash_bytes = Radix::SHA256(combined_hash_str);
            next_hashes_str.push_back(Radix::toHexString(combined_hash_bytes));
        }
        current_hashes_str = next_hashes_str;
    }
    merkleRoot = current_hashes_str[0]; // El último hash restante es la raíz de Merkle
}

// Comprueba si el hash del bloque cumple con el objetivo de dificultad especificado.
// La dificultad se define por el número de ceros iniciales en el hash.
bool Block::checkDifficulty(unsigned int difficulty) const {
    if (hash.empty()) return false;

    // Convierte el hash hexadecimal del bloque a bytes binarios para facilitar la comprobación
    std::vector<uint8_t> hash_bytes(32); // SHA256 produce 32 bytes
    Radix::fromHexString(hash, hash_bytes); // fromHexString está en randomx_util.h

    // Comprueba los bytes completos que deben ser cero
    for (unsigned int i = 0; i < difficulty / 8; ++i) {
        if (hash_bytes[i] != 0x00) {
            return false;
        }
    }

    // Comprueba los bits restantes si la dificultad no es un múltiplo de 8
    unsigned int remaining_bits = difficulty % 8;
    if (remaining_bits > 0) {
        // Crea una máscara para verificar los bits más significativos del byte actual
        uint8_t mask = (1 << (8 - remaining_bits)) - 1; // Ej.: para 4 bits, la máscara es 00001111b
        // Si (byte actual AND NOT mask) no es cero, significa que los bits significativos no son cero.
        if ((hash_bytes[difficulty / 8] & ~mask) != 0x00) {
            return false;
        }
    }
    return true;
}

// Convierte el objeto de bloque a una cadena legible para visualización.
// Ya no necesita el rxContext como parámetro, usa la referencia miembro.
std::string Block::toString() const {
    std::stringstream ss;
    ss << "Block Header:\n";
    ss << "  Version: " << version << "\n";
    ss << "  Prev Hash: " << prevHash << "\n";
    ss << "  Merkle Root: " << merkleRoot << "\n";
    ss << "  Timestamp: " << timestamp << "\n";
    ss << "  Difficulty Target: 0x" << std::hex << difficultyTarget << std::dec << "\n";
    ss << "  Nonce: " << nonce << "\n";
    ss << "  Hash del bloque: " << hash << "\n";

    ss << "Transactions (" << transactions.size() << "):\n";
    // Itera y añade la representación de cadena de cada transacción
    for (const auto& tx : transactions) {
        ss << tx.toString();
    }
    return ss.str();
}

// Valida la integridad de un bloque.
// Ya no necesita el rxContext como parámetro, usa la referencia miembro.
bool Block::isValid() const {
    // 1. Verifica si el hash del bloque se calculó correctamente
    if (calculateHash() != hash) {
        std::cerr << "Error: El hash del bloque no coincide. Recalculado: " << calculateHash() << ", Almacenado: " << hash << std::endl;
        return false;
    }

    // 2. Para el Bloque Génesis, no aplicamos la comprobación de dificultad.
    // El Bloque Génesis se identifica por su versión 1 y un prevHash de puros ceros.
    bool isGenesisBlock = (version == 1 && prevHash == "0000000000000000000000000000000000000000000000000000000000000000");

    if (!isGenesisBlock) { // Solo verifica la dificultad para bloques que no son el génesis
        if (!checkDifficulty(difficultyTarget)) {
            std::cerr << "Error: El hash del bloque no cumple con el objetivo de dificultad." << std::endl;
            return false;
        }
    }

    // 3. Verifica la raíz de Merkle
    if (transactions.empty()) {
        Radix::RandomXHash empty_hash = Radix::SHA256(""); // Se asume SHA256 de string
        if (merkleRoot != Radix::toHexString(empty_hash)) { // Compara strings hexadecimales
            std::cerr << "Error: La raiz de Merkle no coincide para un bloque vacio." << std::endl;
            return false;
        }
    } else {
        std::vector<std::string> current_hashes_str;
        for (const auto& tx : transactions) {
            current_hashes_str.push_back(tx.calculateHash());
        }
        // Recalcula la raíz de Merkle para verificarla
        while (current_hashes_str.size() > 1) {
            if (current_hashes_str.size() % 2 != 0) {
                current_hashes_str.push_back(current_hashes_str.back());
            }
            std::vector<std::string> next_hashes_str;
            for (size_t i = 0; i < current_hashes_str.size(); i += 2) {
                std::string combined_hash_str = current_hashes_str[i] + current_hashes_str[i+1];
                Radix::RandomXHash combined_hash_bytes = Radix::SHA256(combined_hash_str); // Se asume SHA256 de string
                next_hashes_str.push_back(Radix::toHexString(combined_hash_bytes));
            }
            current_hashes_str = next_hashes_str;
        }
        if (merkleRoot != current_hashes_str[0]) {
            std::cerr << "Error: La raiz de Merkle no coincide. Recalculado: " << current_hashes_str[0] << ", Almacenado: " << merkleRoot << std::endl;
            return false;
        }
    }

    // 4. Valida cada transacción en el bloque
    bool hasCoinbase = false;
    for (const auto& tx : transactions) {
        if (tx.isCoinbase) {
            if (hasCoinbase) {
                std::cerr << "Error: El bloque contiene mas de una transaccion de coinbase." << std::endl;
                return false;
            }
            hasCoinbase = true;
        } else {
            // Para transacciones que no son coinbase, valida las firmas y la estructura.
            if (!tx.isValid()) {
                std::cerr << "Error: Transaccion invalida detectada en el bloque (firma incorrecta o estructura invalida)." << std::endl;
                return false;
            }
        }
    }
    // Asegura que un bloque que no sea Génesis tenga exactamente una transacción de coinbase.
    // El bloque Génesis puede no tener transacciones (o no una de coinbase), por lo que se excluye de esta regla.
    if (!isGenesisBlock && !hasCoinbase) {
        std::cerr << "Error: El bloque (no genesis) debe contener exactamente una transaccion de coinbase." << std::endl;
        return false;
    }
    
    return true; // El bloque es válido
}

} // namespace Radix
