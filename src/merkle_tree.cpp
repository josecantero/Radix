#include "merkle_tree.h"
#include "randomx_util.h" // Para RandomXHash, RandomXContext y toHexString

#include <stdexcept>
#include <iostream>
#include <sstream>
#include <iomanip>    // Para std::setw, std::setfill
#include <cstring>    // Para memcpy (C-style header, provides memcpy in global namespace)
#include <openssl/sha.h> // Para SHA256 y SHA256_DIGEST_LENGTH

namespace Radix {

// Constructor
// NOTA IMPORTANTE: El constructor de MerkleTree necesita un RandomXContext para hashear los nodos intermedios.
// En una implementación robusta, este contexto debería pasarse aquí o la clase debería tener una forma de acceder a él.
// Para esta corrección inmediata de compilación, el hashing de los nodos internos del árbol (no las hojas)
// se realizará temporalmente con SHA256 directo, como estaba en el código original que causaba errores.
// La función `hashPair` sí utiliza `RandomXContext`.
MerkleTree::MerkleTree(const std::vector<RandomXHash>& leaves) {
    if (leaves.empty()) {
        rootHash.fill(0); // Árbol Merkle vacío tiene un hash raíz de ceros
        return;
    }

    // Si solo hay una hoja, esa es la raíz
    if (leaves.size() == 1) {
        rootHash = leaves[0];
        return;
    }

    // Copiar las hojas originales
    std::vector<RandomXHash> currentLevel = leaves;

    // Construir el árbol Merkle
    while (currentLevel.size() > 1) {
        std::vector<RandomXHash> nextLevel;
        // Si hay un número impar de nodos, duplica el último
        if (currentLevel.size() % 2 != 0) {
            currentLevel.push_back(currentLevel.back());
        }

        for (size_t i = 0; i < currentLevel.size(); i += 2) {
            std::vector<uint8_t> combinedHashes(currentLevel[i].size() + currentLevel[i+1].size());
            // Concatenar los dos hashes
            memcpy(combinedHashes.data(), currentLevel[i].data(), currentLevel[i].size());
            memcpy(combinedHashes.data() + currentLevel[i].size(), currentLevel[i+1].data(), currentLevel[i+1].size());
            
            // Hash la combinación usando SHA256 directamente como un placeholder temporal.
            // Para una solución robusta y correcta, esta parte debe usar RandomXContext
            // o el hash de la transacción combinada si MerkleTree no tiene el contexto.
            unsigned char digest[SHA256_DIGEST_LENGTH]; // SHA256_DIGEST_LENGTH ahora declarado por openssl/sha.h
            SHA256(combinedHashes.data(), combinedHashes.size(), digest); // SHA256 ahora declarado por openssl/sha.h
            RandomXHash hashedPair;
            memcpy(hashedPair.data(), digest, SHA256_DIGEST_LENGTH);
            
            nextLevel.push_back(hashedPair);
        }
        currentLevel = nextLevel;
    }

    rootHash = currentLevel[0];
}

// Función auxiliar para calcular el hash de un par de nodos en el árbol Merkle.
// Nota: Esta función asume que se le pasa un RandomXContext válido.
RandomXHash MerkleTree::hashPair(const RandomXHash& hash1, const RandomXHash& hash2, Radix::RandomXContext& rxContext) {
    std::vector<uint8_t> combinedHashes(hash1.size() + hash2.size());
    memcpy(combinedHashes.data(), hash1.data(), hash1.size());
    memcpy(combinedHashes.data() + hash1.size(), hash2.data(), hash2.size());

    // El método en RandomXContext se llama 'hash'
    return rxContext.hash(combinedHashes);
}

RandomXHash MerkleTree::getRootHash() const {
    return rootHash;
}

// Implementación de toString()
std::string MerkleTree::toString() const {
    std::stringstream ss;
    ss << "Merkle Root: " << toHexString(rootHash) << "\n";
    return ss.str();
}

} // namespace Radix
