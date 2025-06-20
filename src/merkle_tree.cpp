#include "merkle_tree.h"
#include <iostream>
#include <algorithm> // Para std::copy
#include <stdexcept> // Para std::runtime_error

namespace Radix {

MerkleTree::MerkleTree(const std::vector<RandomXHash>& leafHashes) {
    if (leafHashes.empty()) {
        throw std::runtime_error("Merkle tree cannot be built from empty leaf hashes.");
    }
    leaves = leafHashes;
    buildTree();
}

void MerkleTree::buildTree() {
    if (leaves.empty()) {
        rootHash.fill(0); // O manejar como error, dependiendo de la lógica deseada para árboles vacíos
        return;
    }

    std::vector<RandomXHash> currentLevel = leaves;

    // Si solo hay una hoja, esa es la raíz
    if (currentLevel.size() == 1) {
        rootHash = currentLevel[0];
        return;
    }

    RandomXContext rxContext; // Crear un contexto RandomX para los cálculos

    // Construir los niveles del árbol hasta llegar a la raíz
    while (currentLevel.size() > 1) {
        std::vector<RandomXHash> nextLevel;
        // Si hay un número impar de hashes, duplicar el último
        if (currentLevel.size() % 2 != 0) {
            currentLevel.push_back(currentLevel.back());
        }

        for (size_t i = 0; i < currentLevel.size(); i += 2) {
            RandomXHash combinedHash = hashPair(currentLevel[i], currentLevel[i+1], rxContext);
            nextLevel.push_back(combinedHash);
        }
        currentLevel = nextLevel;
    }
    rootHash = currentLevel[0];
}

RandomXHash MerkleTree::hashPair(const RandomXHash& hash1, const RandomXHash& hash2, RandomXContext& rxContext) {
    std::vector<uint8_t> combinedHashes;
    // Concatenar los dos hashes
    combinedHashes.insert(combinedHashes.end(), hash1.begin(), hash1.end());
    combinedHashes.insert(combinedHashes.end(), hash2.begin(), hash2.end());

    // NOTA: ELIMINAR EL SEGUNDO ARGUMENTO (seed_for_merkle_hash)
    // RandomXContext::calculateHash solo espera los datos a hashear.
    return rxContext.calculateHash(combinedHashes); // ¡CORREGIDO! Solo un argumento
}

RandomXHash MerkleTree::getRootHash() const {
    return rootHash;
}

// Puedes añadir una función de validación aquí si lo deseas
bool MerkleTree::validateTree() const {
    // Esto implicaría reconstruir el árbol y comparar el hash raíz,
    // o verificar los hashes de los nodos intermedios si se almacenaran.
    // Por ahora, asumimos que si se construye, es válido.
    return true;
}

} // namespace Radix