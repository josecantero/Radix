#ifndef BLOCK_H
#define BLOCK_H

#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <memory> // Para std::unique_ptr

#include "transaction.h" // Incluir Transaction para usarlo en el vector
#include "randomx_util.h" // Para RandomXHash

namespace Radix {

struct BlockHeader {
    uint32_t version;
    RandomXHash prevBlockHash;
    RandomXHash merkleRoot;
    uint32_t timestamp;
    uint32_t difficultyTarget;
    uint64_t nonce;
    RandomXHash blockHash; // ¡NUEVO CAMPO: El hash de este propio bloque!
};

class Block {
public:
    BlockHeader header;
    std::vector<std::unique_ptr<Transaction>> transactions;

    // Constructor que toma el vector de transacciones por rvalue reference (std::move)
    Block(uint32_t version, const RandomXHash& prevHash, uint32_t timestamp,
          uint32_t difficultyTarget, std::vector<std::unique_ptr<Transaction>>&& txs); // Fíjate en '&& txs'

    // Constructor por defecto (quizás no sea necesario si siempre usamos el otro)
    Block();

    // --- ¡DESHABILITAR CONSTRUCTOR DE COPIA Y ASIGNACIÓN DE COPIA! ---
    Block(const Block&) = delete; // Elimina el constructor de copia
    Block& operator=(const Block&) = delete; // Elimina el operador de asignación de copia
    // ------------------------------------------------------------------

    // Constructor de movimiento y operador de asignación de movimiento (implícitamente generados por unique_ptr o definidos si hay recursos propios)
    // std::unique_ptr ya maneja el movimiento correctamente.

    void updateMerkleRoot(RandomXContext& rxContext); // Asegura que las transacciones tienen sus TxIds calculados
    RandomXHash calculateHash(RandomXContext& rxContext) const;
    std::string toString() const;
};

} // namespace Radix

#endif // BLOCK_H