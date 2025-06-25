#include "blockchain.h"
#include "merkle_tree.h" 
#include <iostream>
#include <algorithm> // Para std::all_of
#include <vector>    
#include <iomanip>   // Para std::setw, std::setfill

namespace Radix {

// Constructor de la Blockchain
Blockchain::Blockchain(Radix::RandomXContext& rxContext) : currentDifficultyTarget(0xFFFFFF) {
    std::cout << "Creando y minando el Bloque Génesis..." << std::endl;
    createGenesisBlock(rxContext);
}

// Obtener el último bloque en la cadena
const Block& Blockchain::getLastBlock() const {
    return *chain.back();
}

// Creación y minado del Bloque Génesis
void Blockchain::createGenesisBlock(Radix::RandomXContext& rxContext) {
    if (chain.empty()) {
        RandomXHash prevHash; 
        prevHash.fill(0); // Hash previo para el bloque Génesis es todo ceros
        
        std::vector<std::string> genesisTxData; // Vector vacío de transacciones pendientes para el Génesis
        
        auto genesisBlock = std::make_unique<Block>(
            0,                          // version (0 para génesis)
            prevHash,                   // prevHash (todo ceros)
            this->currentDifficultyTarget, 
            genesisTxData,              // Transacciones pendientes (vacío para génesis)
            rxContext                   // Contexto de RandomX
        );

        genesisBlock->mine(rxContext); // Minar el bloque Génesis
        
        std::cout << "Bloque Genesis minado exitosamente con Nonce: " << genesisBlock->nonce << std::endl; 
        chain.push_back(std::move(genesisBlock));
    }
}

// ¡CAMBIO AQUÍ! Definición como método de la clase
bool Blockchain::checkDifficulty(const Radix::RandomXHash& hash, uint32_t target) const {
    // Para esta demo, buscamos que el primer byte del hash sea 0x00.
    // Una implementación real compararía el hash con un "target" numérico derivado de la dificultad.
    return hash[0] == 0x00; 
}

// Función interna para minar un bloque dado
void Blockchain::mineBlockInternal(Block& block, Radix::RandomXContext& rxContext) {
    block.mine(rxContext);
}

// Mina un nuevo bloque y lo devuelve como un unique_ptr
std::unique_ptr<Block> Blockchain::mineNewBlock(Radix::RandomXContext& rxContext, const std::vector<std::string>& pendingTxData) {
    const Block& lastBlock = getLastBlock();
    
    RandomXHash prevHash = lastBlock.hash; 
    uint32_t version = lastBlock.version + 1;

    std::cout << "\nMinando Bloque #" << version << "..." << std::endl;

    auto newBlock = std::make_unique<Block>(
        version,
        prevHash,
        this->currentDifficultyTarget, 
        pendingTxData, 
        rxContext
    );

    mineBlockInternal(*newBlock, rxContext);

    std::cout << "Hash del bloque: " << toHexString(newBlock->hash) << std::endl; 
    
    return newBlock;
}

// Añade un bloque validado a la cadena
bool Blockchain::addBlock(std::unique_ptr<Block> block, Radix::RandomXContext& rxContext, const std::vector<std::string>& currentPendingTransactions) {
    if (!block) {
        std::cerr << "Error: Intentando añadir un bloque nulo." << std::endl;
        return false;
    }

    const Block& lastBlock = getLastBlock();

    // 1. Verificar que el prevHash del nuevo bloque coincide con el hash del último bloque en la cadena
    if (block->prevHash != lastBlock.hash) { 
        std::cerr << "Error: Hash previo del bloque no coincide." << std::endl;
        std::cerr << "  Esperado: " << toHexString(lastBlock.hash) << std::endl; 
        std::cerr << "  Obtenido: " << toHexString(block->prevHash) << std::endl; 
        return false;
    }

    // 2. Verificar la dificultad (que el hash del bloque cumpla con el target)
    if (!checkDifficulty(block->hash, block->difficultyTarget)) { // Usar this->checkDifficulty
        std::cerr << "Error: El hash del bloque no cumple con la dificultad." << std::endl;
        std::cerr << "  Hash del bloque: " << toHexString(block->hash) << std::endl; 
        std::cerr << "  Dificultad esperada (primer byte 0x00): 0x" << std::hex << std::setw(8) << std::setfill('0') << block->difficultyTarget << std::dec << std::endl; 
        return false;
    }

    // 3. Verificar la validez de las transacciones (firmas y estructura)
    for (const auto& tx : block->transactions) {
        // Para verificar si es Coinbase, usamos el getter isCoinbaseTransaction()
        if (!tx.isCoinbaseTransaction()) { // Si no es una transacción Coinbase, verificamos las firmas
            if (!tx.verifySignatures(rxContext)) { 
                std::cerr << "Error: Transacción inválida detectada en el bloque (firma incorrecta o estructura inválida)." << std::endl;
                std::cerr << tx.toString() << std::endl; 
                return false;
            }
        }
    }
    
    // Verificación del Merkle Root del bloque completo
    std::vector<RandomXHash> currentBlockTxHashes;
    for (const auto& tx : block->transactions) {
        currentBlockTxHashes.push_back(tx.getTxId()); // Usar getTxId()
    }
    Radix::MerkleTree calculatedMerkleTree(currentBlockTxHashes);
    Radix::RandomXHash calculatedMerkleRoot = calculatedMerkleTree.getRootHash(); 

    if (calculatedMerkleRoot != block->merkleRoot) { 
        std::cerr << "Error: El Merkle Root calculado no coincide con el Merkle Root del bloque." << std::endl;
        std::cerr << "  Calculado: " << toHexString(calculatedMerkleRoot) << std::endl;
        std::cerr << "  En bloque: " << toHexString(block->merkleRoot) << std::endl; 
        return false;
    }

    // 4. Todas las validaciones pasaron, añadir el bloque a la cadena
    chain.push_back(std::move(block));
    std::cout << "Bloque #" << chain.back()->version << " añadido a la cadena." << std::endl;
    return true;
}

size_t Blockchain::getChainSize() const {
    return chain.size();
}

} // namespace Radix