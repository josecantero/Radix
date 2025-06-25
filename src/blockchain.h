#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include "block.h"
#include "randomx_util.h" // Necesario para RandomXContext
#include <vector>
#include <memory> // Para std::unique_ptr
#include <string>

namespace Radix {

class Blockchain {
public:
    Blockchain(Radix::RandomXContext& rxContext); 

    const Block& getLastBlock() const;
    bool addBlock(std::unique_ptr<Block> block, Radix::RandomXContext& rxContext, const std::vector<std::string>& currentPendingTransactions);
    std::unique_ptr<Block> mineNewBlock(Radix::RandomXContext& rxContext, const std::vector<std::string>& pendingTxData);

    size_t getChainSize() const; 

private:
    std::vector<std::unique_ptr<Block>> chain;
    uint32_t currentDifficultyTarget;

    void createGenesisBlock(Radix::RandomXContext& rxContext);
    void mineBlockInternal(Block& block, Radix::RandomXContext& rxContext);
    
    // ¡CAMBIO AQUÍ! Declaración como método privado de la clase
    bool checkDifficulty(const RandomXHash& hash, uint32_t target) const; 
};

} // namespace Radix

#endif // BLOCKCHAIN_H