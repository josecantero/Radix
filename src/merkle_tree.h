#ifndef MERKLE_TREE_H
#define MERKLE_TREE_H

#include <vector>
#include <array>
#include <string>
#include <cstdint> // Para uint8_t

#include "randomx_util.h" // Para RandomXHash y RandomXContext

namespace Soverx {

class MerkleTree {
public:
    MerkleTree(const std::vector<RandomXHash>& leaves);
    
    RandomXHash getRootHash() const;
    
    // Declaración correcta de toString
    std::string toString() const; 

private:
    RandomXHash rootHash;

    // Función auxiliar para calcular el hash de un par de nodos
    // Ahora es un método estático o se maneja la instancia de rxContext de otra forma.
    // Para simplificar y dado que el MerkleTree necesita una RXContext para hashear,
    // se puede pasar como parámetro donde se necesite o la MerkleTree lo guarde.
    // Dado el error anterior, lo moveremos al constructor si es para inicialización
    // o se pasará en funciones que requieran hashing.
    // La versión anterior tenía un placeholder para SHA256 directo sin RXContext
    // lo que causó algunos de los errores.
    static RandomXHash hashPair(const RandomXHash& hash1, const RandomXHash& hash2, Soverx::RandomXContext& rxContext);
};

} // namespace Soverx

#endif // MERKLE_TREE_H
