#include "merkle_tree.h"
#include <algorithm> // Para std::vector::insert y otras utilidades
#include <stdexcept>

namespace Radix {

MerkleTree::MerkleTree(const std::vector<RandomXHash>& transactionHashes, RandomXContext& rxContext)
    : leaves(transactionHashes) {

    if (leaves.empty()) {
        // En Bitcoin, un bloque sin transacciones no es válido.
        // Pero para el génesis o bloques con solo coinbase, se requiere un hash.
        // La raíz Merkle de un bloque génesis (o sin txs) puede ser el hash del coinbase.
        // Si no hay transacciones en absoluto, puede ser un hash de ceros.
        merkleRoot.fill(0); // Raíz Merkle nula si no hay transacciones.
        return;
    }

    // Si solo hay una transacción (ej. solo coinbase), su hash es la raíz Merkle
    if (leaves.size() == 1) {
        merkleRoot = leaves[0];
        return;
    }

    std::vector<RandomXHash> currentLevel = leaves;

    // Construir el árbol de abajo hacia arriba
    while (currentLevel.size() > 1) {
        std::vector<RandomXHash> nextLevel;
        for (size_t i = 0; i < currentLevel.size(); i += 2) {
            RandomXHash h1 = currentLevel[i];
            RandomXHash h2;

            // Si hay un número impar de hashes, el último se duplica (como en Bitcoin)
            if (i + 1 < currentLevel.size()) {
                h2 = currentLevel[i+1];
            } else {
                h2 = h1; // Duplicar el último hash
            }
            nextLevel.push_back(hashPair(h1, h2, rxContext));
        }
        currentLevel = nextLevel;
    }

    merkleRoot = currentLevel[0];
}

RandomXHash MerkleTree::getMerkleRoot() const {
    return merkleRoot;
}

RandomXHash MerkleTree::hashPair(const RandomXHash& h1, const RandomXHash& h2, RandomXContext& rxContext) {
    // Concatenar los dos hashes
    std::vector<uint8_t> combinedHashes;
    combinedHashes.reserve(h1.size() + h2.size());
    combinedHashes.insert(combinedHashes.end(), h1.begin(), h1.end());
    combinedHashes.insert(combinedHashes.end(), h2.begin(), h2.end());

    // NOTA: Similar a Transaction::calculateHash, aquí también se usaría SHA256
    // en una implementación real para el hashing del Merkle Tree.
    // Usamos RandomXContext para simular el hashing por ahora.
    std::vector<uint8_t> seed_for_merkle_hash(RANDOMX_HASH_SIZE, 0); // Semilla fija
    return rxContext.calculateHash(combinedHashes, seed_for_merkle_hash);
}

} // namespace Radix