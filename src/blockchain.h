#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <vector>
#include <memory> // Para std::unique_ptr
#include "block.h"
#include "randomx_util.h"
#include "transaction.h"


// Declaraciones forward para evitar dependencias circulares completas
namespace Radix {
    class Block;
    class Transaction;
    class RandomXContext; // Agregado si no estaba ya
    using RandomXHash = std::array<uint8_t, 32>; // Definición de RandomXHash si no está en randomx_util.h
}

namespace Radix {

class Blockchain {
public:
    Blockchain();
    void createGenesisBlock(RandomXContext& rxContext);
    std::unique_ptr<Block> mineNewBlock(RandomXContext& rxContext, const std::vector<std::string>& pendingTxData);
    bool addBlock(std::unique_ptr<Block> block, RandomXContext& rxContext, const std::vector<std::string>& currentPendingTxData);
    const Block& getLastBlock() const;
    uint32_t getCurrentDifficultyTarget() const; // Para obtener el target de dificultad
    // --- AÑADE ESTO ---
    size_t getChainSize() const; // Nuevo método público para obtener el tamaño de la cadena
    // ------------------

private:
    std::vector<std::unique_ptr<Block>> chain; // Private por encapsulamiento

    // Funciones auxiliares privadas
    void mineBlockInternal(Block& block, RandomXContext& rxContext);
    bool checkDifficulty(const RandomXHash& hash, uint32_t target) const;
};

} // namespace Radix

#endif // BLOCKCHAIN_H