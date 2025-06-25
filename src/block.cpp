#include "block.h"
#include "randomx_util.h" // Para toHexString
#include "merkle_tree.h"
#include <iostream>
#include <sstream>
#include <iomanip> // Para std::setw, std::setfill
#include <chrono> // Para std::chrono
#include <algorithm>

namespace Radix {

// Constructor
Block::Block(uint32_t version, const RandomXHash& prevHash, uint32_t difficultyTarget, const std::vector<std::string>& pendingTxData, Radix::RandomXContext& rxContext)
    : version(version),
      prevHash(prevHash),
      difficultyTarget(difficultyTarget),
      nonce(0) // Inicializamos el nonce a 0, se encontrará con la minería
{
    this->timestamp = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    
    // Un hash previo compuesto solo de ceros indica el bloque Génesis.
    // std::all_of es la forma correcta de verificar si un std::array está lleno de un valor.
    bool isGenesisBlock = std::all_of(prevHash.begin(), prevHash.end(), [](uint8_t b){ return b == 0; });

    if (isGenesisBlock) {
        // Bloque Génesis: Recompensa inicial para el minero (50 RDX)
        Rads genesisReward = 50000000000ULL; // 50 RDX = 50 * 10^9 Rads
        // Usamos el constructor de Transaction para Coinbase (solo outputs)
        transactions.emplace_back(std::vector<Radix::TxOutput>{Radix::TxOutput{genesisReward, "R1mFGenesisMinerAddress"}}, rxContext);
    } else {
        // Bloques subsiguientes: recompensa para el minero (10 RDX) + transacciones del pool
        Rads blockReward = 10000000000ULL; // 10 RDX = 10 * 10^9 Rads
        // Usamos el constructor de Transaction para Coinbase
        transactions.emplace_back(std::vector<Radix::TxOutput>{Radix::TxOutput{blockReward, "R1mFMinerAddressExample"}}, rxContext);
        
        // Convertir pendingTxData (strings) en objetos Transaction dummy por ahora
        // NOTA: Estas transacciones no son reales aún, son solo place-holders
        // La implementación real de transacciones se hará con UTXO y firmas.
        for (const std::string& txDataStr : pendingTxData) {
            // Crear inputs y outputs dummy para la demostración
            Radix::TxInput dummyInput; // Input dummy
            dummyInput.prevTxId.fill(0); // Rellenar con ceros (simulando TxID de una transacción anterior)
            dummyInput.outputIndex = 0;
            dummyInput.signature.assign(64, 0xAA); // Firma dummy (64 bytes, valor arbitrario)
            dummyInput.pubKey.assign(65, 0xBB);   // Clave pública dummy (65 bytes, valor arbitrario - formato uncompressed)
            
            Radix::TxOutput dummyOutput{1ULL, "R1mFRecipientAddress"}; // Output dummy

            // Usar el constructor general de Transaction
            transactions.emplace_back(std::vector<Radix::TxInput>{dummyInput}, std::vector<Radix::TxOutput>{dummyOutput}, rxContext);
        }
    }

    // Calcular los TxId para todas las transacciones recién agregadas
    for (auto& tx : transactions) {
        tx.calculateTxId(rxContext); // Usa calculateTxId, no calculateHash
    }
    
    this->merkleRoot = getMerkleRoot();
    this->hash.fill(0); // Se calculará al minar
}

RandomXHash Block::calculateHash(RandomXContext& rxContext) const {
    std::vector<uint8_t> headerBytes = serializeHeader();
    // CORRECCIÓN: El método en RandomXContext se renombró a 'hash'
    return rxContext.hash(headerBytes);
}

void Block::mine(RandomXContext& rxContext) {
    std::cout << "Minando bloque " << (version == 0 ? "Genesis" : ("#" + std::to_string(version))) << "..." << std::endl;
    
    RandomXHash tempHash;
    do {
        nonce++;
        tempHash = calculateHash(rxContext);
    } while (tempHash[0] != 0x00); // Condición de dificultad: para esta demo, que el hash empiece con 00

    this->hash = tempHash;
    std::cout << "Bloque " << (version == 0 ? "Genesis" : ("#" + std::to_string(version))) << " minado exitosamente con Nonce: " << nonce << std::endl;
}

std::vector<uint8_t> Block::serializeHeader() const {
    std::vector<uint8_t> headerBytes;

    // Version (uint32_t)
    for (int i = 0; i < 4; ++i) {
        headerBytes.push_back((version >> (8 * i)) & 0xFF);
    }
    // Prev Hash (32 bytes)
    headerBytes.insert(headerBytes.end(), prevHash.begin(), prevHash.end());
    // Merkle Root (32 bytes)
    headerBytes.insert(headerBytes.end(), merkleRoot.begin(), merkleRoot.end());
    // Timestamp (uint32_t)
    for (int i = 0; i < 4; ++i) {
        headerBytes.push_back((timestamp >> (8 * i)) & 0xFF);
    }
    // Difficulty Target (uint32_t)
    for (int i = 0; i < 4; ++i) {
        headerBytes.push_back((difficultyTarget >> (8 * i)) & 0xFF);
    }
    // Nonce (uint64_t)
    for (int i = 0; i < 8; ++i) {
        headerBytes.push_back((nonce >> (8 * i)) & 0xFF);
    }

    return headerBytes;
}

RandomXHash Block::getMerkleRoot() const {
    if (transactions.empty()) {
        RandomXHash emptyRoot;
        emptyRoot.fill(0);
        return emptyRoot;
    }

    // Obtener los hashes de todas las transacciones (sus TxId)
    std::vector<RandomXHash> txHashes;
    for (const auto& tx : transactions) {
        txHashes.push_back(tx.getTxId()); // Usamos el getter getTxId()
    }

    MerkleTree merkleTree(txHashes);
    return merkleTree.getRootHash();
}

std::string Block::toString(Radix::RandomXContext& rxContext) const {
    std::stringstream ss;
    ss << "Block Header:\n";
    ss << "  Version: " << version << "\n";
    ss << "  Prev Hash: " << toHexString(prevHash) << "\n";
    ss << "  Merkle Root: " << toHexString(merkleRoot) << "\n";
    ss << "  Timestamp: " << timestamp << "\n";
    ss << "  Difficulty Target: 0x" << std::hex << std::setfill('0') << std::setw(8) << difficultyTarget << std::dec << "\n";
    ss << "  Nonce: " << nonce << "\n";
    ss << "  Hash del bloque: " << toHexString(hash) << "\n";
    ss << "Transactions (" << transactions.size() << "):\n";
    for (const auto& tx : transactions) {
        ss << tx.toString();
    }
    return ss.str();
}

} // namespace Radix
