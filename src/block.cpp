#include "block.h"
#include <sstream>
#include <iomanip>
#include <chrono>
#include <vector> // Necesario para std::vector

namespace Radix {

BlockHeader::BlockHeader() : version(1), timestamp(0), difficultyTarget(0), nonce(0) {
    prevBlockHash.fill(0);
    merkleRoot.fill(0);
}

std::vector<uint8_t> BlockHeader::serialize() const {
    std::vector<uint8_t> data;
    data.reserve(80); // Tamaño aproximado de la cabecera

    // Seriali
    // (Simplificado, sin preocuparse por la endianness del sistzar campos en formato little-endian (como Bitcoin)ema directamente)

    // Version (4 bytes)
    data.push_back(static_cast<uint8_t>(version & 0xFF));
    data.push_back(static_cast<uint8_t>((version >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>((version >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((version >> 24) & 0xFF));

    // PrevBlockHash (32 bytes)
    data.insert(data.end(), prevBlockHash.begin(), prevBlockHash.end());

    // MerkleRoot (32 bytes)
    data.insert(data.end(), merkleRoot.begin(), merkleRoot.end());

    // Timestamp (4 bytes)
    data.push_back(static_cast<uint8_t>(timestamp & 0xFF));
    data.push_back(static_cast<uint8_t>((timestamp >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>((timestamp >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((timestamp >> 24) & 0xFF));

    // DifficultyTarget (4 bytes)
    data.push_back(static_cast<uint8_t>(difficultyTarget & 0xFF));
    data.push_back(static_cast<uint8_t>((difficultyTarget >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>((difficultyTarget >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((difficultyTarget >> 24) & 0xFF));

    // Nonce (4 bytes)
    data.push_back(static_cast<uint8_t>(nonce & 0xFF));
    data.push_back(static_cast<uint8_t>((nonce >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>((nonce >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((nonce >> 24) & 0xFF));

    return data;
}

Block::Block() {
    // Inicializar timestamp con el tiempo actual
    header.timestamp = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

Radix::RandomXHash Block::calculateHash(Radix::RandomXContext& rxContext) const {
    std::vector<uint8_t> headerData = header.serialize();
    // La semilla para RandomX es el hash del bloque anterior.
    // Esto es crucial para RandomX en PoW.

    // CONVERTIMOS std::array<uint8_t, 32> a std::vector<uint8_t>
    std::vector<uint8_t> prevBlockHashVector(header.prevBlockHash.begin(), header.prevBlockHash.end());

    return rxContext.calculateHash(headerData, prevBlockHashVector);
}

void Block::addTransaction(std::unique_ptr<Transaction> tx) {
    transactions.push_back(std::move(tx)); // Mueve el unique_ptr al vector
}

void Block::updateMerkleRoot(RandomXContext& rxContext) {
    std::vector<RandomXHash> txHashes;
    // La primera transacción debe ser la Coinbase (recompensa del minero)
    // Si no hay transacciones (solo un bloque génesis sin coinbase),
    // el Merkle Root puede ser el hash de un bloque vacío o similar.
    // Bitcoin permite un bloque génesis sin transacciones.
    if (transactions.empty()) {
        header.merkleRoot.fill(0); // Si no hay transacciones, la raíz Merkle es 0 (o hash especial)
        return;
    }

    // Recopilar los hashes de todas las transacciones
    for (const auto& tx_ptr : transactions) {
        txHashes.push_back(tx_ptr->txId); // Usar el TxId ya calculado
    }

    // Construir el árbol Merkle
    MerkleTree merkleTree(txHashes, rxContext);
    header.merkleRoot = merkleTree.getMerkleRoot();
}

std::string Block::toString() const {
    std::stringstream ss;
    ss << "Block Header:\n"
       << "  Version: " << header.version << "\n"
       << "  Prev Hash: " << toHexString(header.prevBlockHash) << "\n"
       << "  Merkle Root: " << toHexString(header.merkleRoot) << "\n"
       << "  Timestamp: " << header.timestamp << "\n"
       << "  Difficulty Target: 0x" << std::hex << header.difficultyTarget << std::dec << "\n"
       << "  Nonce: " << header.nonce << "\n";
    
    ss << "Transactions (" << transactions.size() << "):\n";
    for (const auto& tx_ptr : transactions) {
        ss << tx_ptr->toString() << "\n";
    }
    
    return ss.str();
}

} // namespace Radix