#ifndef MERKLE_TREE_H
#define MERKLE_TREE_H

#include <vector>
#include <array>
#include <cstdint> // Para uint8_t
#include "randomx_util.h" // Para RandomXHash y RandomXContext

namespace Radix {

// Declaración forward de RandomXContext si no se incluye randomx_util.h completamente
// class RandomXContext; // Ya incluido arriba

class MerkleTree {
public:
    // Constructor que toma las hojas (hashes de transacciones) y un contexto RandomX
    // ¡CORREGIDO EL CONSTRUCTOR PARA REFLEJAR LA IMPLEMENTACIÓN!
    MerkleTree(const std::vector<RandomXHash>& leafHashes);

    // Obtiene el hash raíz del árbol Merkle
    RandomXHash getRootHash() const;

    // Función de validación (ejemplo, la implementación actual es un placeholder)
    bool validateTree() const;

private:
    std::vector<RandomXHash> leaves; // Hashes de las transacciones (hojas)
    RandomXHash rootHash;            // Hash raíz del árbol Merkle

    // Función privada para construir el árbol Merkle
    // ¡CORREGIDO PARA HACERLA PRIVADA Y SIN ARGUMENTOS EXPLICITOS EN LA DECLARACIÓN!
    void buildTree();

    // Función para hashear un par de hashes
    RandomXHash hashPair(const RandomXHash& hash1, const RandomXHash& hash2, RandomXContext& rxContext);
};

} // namespace Radix

#endif // MERKLE_TREE_H