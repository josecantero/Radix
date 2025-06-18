#ifndef MERKLE_TREE_H
#define MERKLE_TREE_H

#include <vector>
#include "randomx_util.h" // Para RandomXHash (TxId)
#include <memory> // Para std::unique_ptr

namespace Radix {

class MerkleTree {
public:
    // Construye el árbol Merkle a partir de una lista de hashes de transacción
    MerkleTree(const std::vector<RandomXHash>& transactionHashes, RandomXContext& rxContext);

    // Obtiene la raíz Merkle del árbol
    RandomXHash getMerkleRoot() const;

private:
    std::vector<RandomXHash> leaves; // Los hashes de las transacciones
    RandomXHash merkleRoot; // La raíz final

    // Función auxiliar para calcular el hash combinado de dos hashes
    RandomXHash hashPair(const RandomXHash& h1, const RandomXHash& h2, RandomXContext& rxContext);
};

} // namespace Radix

#endif // MERKLE_TREE_H