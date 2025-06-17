#include "block.h"
#include <sstream>
#include <iomanip>
#include <chrono>
#include <vector> // Necesario para std::vector

namespace Radix {

std::vector<uint8_t> BlockHeader::serialize() const {
    std::vector<uint8_t> data;
    data.reserve(80); // Tamaño aproximado de la cabecera

    // Serializar campos en formato little-endian (como Bitcoin)
    // (Simplificado, sin preocuparse por la endianness del sistema directamente)

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

    return rxContext.calculateHash(headerData, prevBlockHashVector); // <-- CAMBIO AQUI
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
    return ss.str();
}

} // namespace Radix