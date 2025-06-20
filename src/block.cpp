#include "block.h"
#include <iostream>
#include <sstream>
#include <iomanip> // Para std::setw, std::setfill
#include <algorithm> // Para std::copy
#include <stdexcept> // Para std::runtime_error

namespace Radix {

// Constructor por defecto
Block::Block() {
    header.version = 0;
    header.prevBlockHash.fill(0);
    header.merkleRoot.fill(0);
    header.timestamp = 0;
    header.difficultyTarget = 0;
    header.nonce = 0;
    header.blockHash.fill(0); // Inicializar el nuevo campo
}

// Constructor principal que toma el vector de transacciones por rvalue reference
Block::Block(uint32_t version, const RandomXHash& prevHash, uint32_t timestamp,
             uint32_t difficultyTarget, std::vector<std::unique_ptr<Transaction>>&& txs) // Fíjate en '&& txs'
    : transactions(std::move(txs)) // Mueve las transacciones
{
    header.version = version;
    header.prevBlockHash = prevHash;
    header.timestamp = timestamp;
    header.difficultyTarget = difficultyTarget;
    header.nonce = 0; // Se inicializa en 0 para la minería
    header.merkleRoot.fill(0); // Se calculará después en updateMerkleRoot
    header.blockHash.fill(0); // Se calculará y asignará después de la minería
}

void Block::updateMerkleRoot(RandomXContext& rxContext) {
    if (transactions.empty()) {
        header.merkleRoot.fill(0); // O un hash de un bloque vacío si es la regla
        return;
    }

    // Calcula los TxIds para todas las transacciones si aún no lo tienen
    std::vector<RandomXHash> txHashes;
    for (const auto& tx_ptr : transactions) {
        // Asegúrate de que el TxId esté calculado antes de usarlo en el Merkle Tree
        // Solo recalcular si es necesario, o asume que ya fue calculado al crear la Tx.
        // Aquí asumimos que tx_ptr->txId ya está calculado.
        txHashes.push_back(tx_ptr->txId);
    }

    // Si solo hay una transacción (ej. Coinbase en el génesis), su TxId es el Merkle Root.
    if (txHashes.size() == 1) {
        header.merkleRoot = txHashes[0];
        return;
    }

    // Construir el Merkle Tree
    while (txHashes.size() > 1) {
        if (txHashes.size() % 2 != 0) {
            txHashes.push_back(txHashes.back()); // Duplicar el último hash si es impar
        }
        std::vector<RandomXHash> newLevelHashes;
        for (size_t i = 0; i < txHashes.size(); i += 2) {
            std::vector<uint8_t> combinedHashData;
            for (uint8_t byte : txHashes[i]) {
                combinedHashData.push_back(byte);
            }
            for (uint8_t byte : txHashes[i+1]) {
                combinedHashData.push_back(byte);
            }
            newLevelHashes.push_back(rxContext.calculateHash(combinedHashData));
        }
        txHashes = newLevelHashes;
    }
    header.merkleRoot = txHashes[0];
}

RandomXHash Block::calculateHash(RandomXContext& rxContext) const {
    std::vector<uint8_t> headerData;

    // Serializar version (uint32_t)
    for (int i = 0; i < 4; ++i) {
        headerData.push_back((header.version >> (8 * i)) & 0xFF);
    }
    // Serializar prevBlockHash (32 bytes)
    for (uint8_t byte : header.prevBlockHash) {
        headerData.push_back(byte);
    }
    // Serializar merkleRoot (32 bytes)
    for (uint8_t byte : header.merkleRoot) {
        headerData.push_back(byte);
    }
    // Serializar timestamp (uint32_t)
    for (int i = 0; i < 4; ++i) {
        headerData.push_back((header.timestamp >> (8 * i)) & 0xFF);
    }
    // Serializar difficultyTarget (uint32_t)
    for (int i = 0; i < 4; ++i) {
        headerData.push_back((header.difficultyTarget >> (8 * i)) & 0xFF);
    }
    // Serializar nonce (uint64_t)
    for (int i = 0; i < 8; ++i) {
        headerData.push_back((header.nonce >> (8 * i)) & 0xFF);
    }

    // Calcular el hash del header
    return rxContext.calculateHash(headerData);
}

std::string Block::toString() const {
    std::stringstream ss;
    ss << "Block Header:\n";
    ss << "  Version: " << header.version << "\n";
    ss << "  Prev Hash: " << toHexString(header.prevBlockHash) << "\n";
    ss << "  Merkle Root: " << toHexString(header.merkleRoot) << "\n";
    ss << "  Timestamp: " << header.timestamp << "\n";
    ss << "  Difficulty Target: 0x" << std::hex << std::setw(6) << std::setfill('0') << header.difficultyTarget << std::dec << "\n";
    ss << "  Nonce: " << header.nonce << "\n";
    ss << "  Hash del bloque: " << toHexString(header.blockHash) << "\n"; // Ahora podemos mostrarlo
    ss << "Transactions (" << transactions.size() << "):\n";
    for (const auto& tx : transactions) {
        ss << tx->toString() << "\n";
    }
    return ss.str();
}

} // namespace Radix