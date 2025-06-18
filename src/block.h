#ifndef BLOCK_H
#define BLOCK_H

#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <memory> // Para std::unique_ptr
#include "randomx_util.h" // Para RandomXHash
#include "transaction.h"
#include "merkle_tree.h"

namespace Radix {

// Estructura de la cabecera de un bloque de Radix (RDX)
// Similar a la de Bitcoin, pero adaptada.
struct BlockHeader {
    int32_t version;         // Versión del bloque
    RandomXHash prevBlockHash; // Hash del bloque anterior (semilla para RandomX)
    RandomXHash merkleRoot;    // Hash de la raíz Merkle de las transacciones (placeholder por ahora)
    uint32_t timestamp;      // Marca de tiempo del bloque
    uint32_t difficultyTarget; // Objetivo de dificultad
    uint32_t nonce;          // Nonce para la prueba de trabajo

    BlockHeader();

    // Constructor por defecto
    /*BlockHeader() : version(1), timestamp(0), difficultyTarget(0), nonce(0) {
        prevBlockHash.fill(0);
        merkleRoot.fill(0);
    }*/

    // Serializa la cabecera del bloque a un vector de bytes para hashing
    std::vector<uint8_t> serialize() const;
};

// Estructura de un bloque completo (por ahora, solo cabecera)
class Block {
public:
    BlockHeader header;
    std::vector<std::unique_ptr<Transaction>> transactions;

    Block(); // Constructor por defecto

    // Calcula el hash del bloque usando RandomX
    RandomXHash calculateHash(RandomXContext& rxContext) const;

    // Añade una transacción al bloque
    void addTransaction(std::unique_ptr<Transaction> tx);

    // Actualiza la raíz Merkle del bloque basándose en las transacciones actuales
    void updateMerkleRoot(RandomXContext& rxContext);


    // Para representar el bloque de forma legible
    std::string toString() const;
};

} // namespace Radix

#endif // BLOCK_H