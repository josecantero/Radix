#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <vector>
#include <memory> // Para std::unique_ptr
#include "block.h"
#include "randomx_util.h"
#include "transaction.h"

namespace Radix {

class Blockchain {
public:
    Blockchain();

    // Añade un bloque a la cadena (verifica si es válido)
    bool addBlock(std::unique_ptr<Block> newBlock, RandomXContext& rxContext, const std::vector<std::string>& pendingTxData); //rxContext para validación

    // Obtiene el último bloque de la cadena
    const Block& getLastBlock() const;

    // Demostración de minado de un nuevo bloque
    std::unique_ptr<Block> mineNewBlock(RandomXContext& rxContext, const std::vector<std::string>& pendingTxData);

    // Obtiene el objetivo de dificultad actual (simplificado)
    uint32_t getCurrentDifficultyTarget() const;

    // Verifica si un hash cumple con el objetivo de dificultad
    bool checkDifficulty(const RandomXHash& hash, uint32_t target) const;

    // Crea el bloque génesis
    void createGenesisBlock(RandomXContext& rxContext);

private:
    //std::vector<Block> chain;
    std::vector<std::unique_ptr<Block>> chain;
    //RandomXHash genesisBlockTargetHash; // El hash que debe cumplir el bloque génesis

    // Genera la transacción Coinbase para la recompensa del minero
    std::unique_ptr<CoinbaseTransaction> createCoinbaseTx(uint32_t blockHeight, const std::string& minerAddress, RandomXContext& rxContext);
};

} // namespace Radix

#endif // BLOCKCHAIN_H