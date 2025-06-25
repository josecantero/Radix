#ifndef BLOCK_H
#define BLOCK_H

#include <cstdint>
#include <vector>
#include <string>
#include <memory> // Para std::unique_ptr
#include "transaction.h"
#include "merkle_tree.h"
#include "randomx_util.h" // Necesario para RandomXHash y RandomXContext

namespace Radix {

class RandomXContext; // Declaración adelantada

class Block {
public:
    uint32_t version;
    RandomXHash prevHash;
    RandomXHash merkleRoot;
    uint32_t timestamp;
    uint32_t difficultyTarget;
    uint64_t nonce;
    RandomXHash hash;
    std::vector<Transaction> transactions;

    // Constructor
    Block(uint32_t version, const RandomXHash& prevHash, uint32_t difficultyTarget, const std::vector<std::string>& pendingTxData, Radix::RandomXContext& rxContext);

    // Recompute the block hash
    RandomXHash calculateHash(RandomXContext& rxContext) const;
    
    // Método para minar el bloque (encuentra el nonce)
    void mine(RandomXContext& rxContext);

    // Serializa el header del bloque
    std::vector<uint8_t> serializeHeader() const;

    // Obtener el Merkle Root de las transacciones
    RandomXHash getMerkleRoot() const;

    // Ahora toString() acepta un RandomXContext
    std::string toString(Radix::RandomXContext& rxContext) const;

private:
    // Helper para serializar las transacciones para el Merkle Tree
    // NOTA: Esta función privada 'getTransactionHashes' no es estrictamente necesaria
    // si getMerkleRoot ya itera sobre las transacciones directamente para sus hashes.
    // La elimino en .cpp, pero la dejo comentada aquí por si en el futuro se quiere usar.
    // std::vector<RandomXHash> getTransactionHashes(Radix::RandomXContext& rxContext) const;
};

} // namespace Radix

#endif // BLOCK_H