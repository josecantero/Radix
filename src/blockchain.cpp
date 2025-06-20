#include "blockchain.h"
#include "block.h"
#include "transaction.h"
#include "randomx_util.h" // Para toHexString
#include <iostream>
#include <limits> // Para std::numeric_limits
// #include <ctime>  // ¡ELIMINADO! Ya no es necesario si std::time se resuelve con <chrono>
#include <chrono> // Para std::chrono::system_clock::now() y otras funciones de tiempo
#include <iomanip> // Para std::setw, std::setfill en mensajes de error

namespace Radix {

// Constructor de Blockchain
Blockchain::Blockchain() {
    // La cadena se inicializará con el bloque Génesis
}

// Crea el Bloque Génesis
void Blockchain::createGenesisBlock(RandomXContext& rxContext) {
    // Crear la transacción de recompensa para el minero (Coinbase)
    // Asignamos una dirección de minero de ejemplo por ahora.
    // La recompensa inicial es un valor arbitrario, ej. 50 Radix = 50,000,000,000 Rads
    Rads genesisReward = 50000000000ULL; // 50 RDX = 50 * 10^9 Rads
    Address genesisMinerAddress = "R1mFGenesisMinerAddress"; // Dirección de ejemplo para el minero del Génesis

    // La transacción Coinbase no tiene inputs que gasten fondos, solo crea nuevos.
    // El campo 'data' puede ser un mensaje arbitrario.
    CoinbaseTransaction coinbaseTx(genesisReward, genesisMinerAddress, "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks");

    // Calcular el TxId de la transacción Coinbase
    coinbaseTx.txId = coinbaseTx.calculateHash(rxContext);

    // Crear el bloque Génesis
    // No tiene Previous Hash (todos ceros)
    RandomXHash prevHash;
    prevHash.fill(0);

    // Las transacciones pendientes para el Génesis solo incluyen la Coinbase
    std::vector<std::unique_ptr<Transaction>> genesisTransactions;
    genesisTransactions.push_back(std::make_unique<CoinbaseTransaction>(std::move(coinbaseTx))); // Movemos la transacción

    std::cout << "Minando bloque Genesis..." << std::endl;
    
    // Obtener el timestamp actual usando chrono
    uint32_t currentTimestamp = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                    std::chrono::system_clock::now().time_since_epoch()).count());

    // Crear el bloque Génesis usando el constructor que toma rvalue reference
    std::unique_ptr<Block> genesisBlock = std::make_unique<Block>(
        1, // Version
        prevHash,
        currentTimestamp, // Timestamp generado con chrono
        getCurrentDifficultyTarget(),
        std::move(genesisTransactions) // Mover las transacciones al bloque
    );

    // Minar el bloque Génesis
    mineBlockInternal(*genesisBlock, rxContext);

    // Añadir el bloque minado a la cadena
    chain.push_back(std::move(genesisBlock));
    std::cout << "Bloque Genesis minado exitosamente con Nonce: " << chain.back()->header.nonce << std::endl;
}

// Calcula la dificultad actual (ej. un byte inicial de 0)
uint32_t Blockchain::getCurrentDifficultyTarget() const {
    // Esto es una dificultad fija para la demo.
    // En una blockchain real, se ajustaría dinámicamente.
    return 0x00FFFFFF; // Representa que el primer byte del hash debe ser 0
}

// Verifica si un hash cumple con la dificultad
bool Blockchain::checkDifficulty(const RandomXHash& hash, uint32_t target) const {
    // Para 0x00FFFFFF, solo necesitamos verificar que el primer byte sea 0x00
    // Esto significa que el hash resultante debe ser menor o igual que 0x00FFFFFF...
    // Un hash con ceros iniciales cumple la dificultad.
    return hash[0] == 0x00;
}

// Función interna para minar un bloque dado
void Blockchain::mineBlockInternal(Block& block, RandomXContext& rxContext) {
    block.updateMerkleRoot(rxContext); // Asegurarse de que el Merkle Root esté actualizado
    block.header.nonce = 0; // Reiniciar el nonce para empezar a minar

    RandomXHash currentHash;
    while (true) {
        currentHash = block.calculateHash(rxContext);
        if (checkDifficulty(currentHash, block.header.difficultyTarget)) {
            block.header.blockHash = currentHash; // Asignar el hash encontrado al bloque
            break;
        }
        block.header.nonce++;
    }
}

// Mina un nuevo bloque con transacciones pendientes
std::unique_ptr<Block> Blockchain::mineNewBlock(Radix::RandomXContext& rxContext,
                                                  const std::vector<std::string>& pendingTxData) {
    if (chain.empty()) {
        std::cerr << "Error: No se puede minar un nuevo bloque sin un Bloque Genesis." << std::endl;
        return nullptr;
    }

    const Block& lastBlock = getLastBlock();
    RandomXHash prevHash = lastBlock.header.blockHash; // Usamos el blockHash del bloque anterior
    
    // Obtener el timestamp actual usando chrono
    uint32_t currentTimestamp = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                    std::chrono::system_clock::now().time_since_epoch()).count());
    
    uint32_t difficulty = getCurrentDifficultyTarget();

    // Crear la transacción Coinbase para este nuevo bloque
    // Recompensa de 10 RDX (10,000,000,000 Rads) para el minero
    Rads blockReward = 10000000000ULL;
    Address minerAddress = "R1mFMinerAddressExample"; // Dirección de ejemplo para el minero
    CoinbaseTransaction coinbaseTx(blockReward, minerAddress, "Coinbase for Block " + std::to_string(chain.size())); // Usamos chain.size() para el número de bloque

    // Calcular el TxId de la transacción Coinbase
    coinbaseTx.txId = coinbaseTx.calculateHash(rxContext);

    // Preparar todas las transacciones para el nuevo bloque
    std::vector<std::unique_ptr<Transaction>> blockTransactions;
    blockTransactions.push_back(std::make_unique<CoinbaseTransaction>(std::move(coinbaseTx)));

    // Convertir las strings de pendingTxData en objetos Transaction simplificados
    // NOTA: Estas transacciones AÚN NO SON COMPLETAMENTE REALISTAS (no gastan UTXOs reales, no hay firmas)
    // Esto es solo para poblar el bloque con algo que tiene un TxId y es contable para el Merkle tree.
    for (const std::string& txData : pendingTxData) {
        // Por ahora, creamos transacciones "dummy" con 0 inputs y 1 output para un destinatario ficticio
        // con un valor de 1 Rad y la data que nos pasaron. Esto cambiará con UTXOs y firmas.
        std::vector<TxInput> dummyInputs; // Transacción sin inputs reales por ahora
        std::vector<TxOutput> dummyOutputs;
        dummyOutputs.emplace_back(1ULL, "R1mFRecipientAddress"); // 1 Rad a una dirección dummy

        std::unique_ptr<Transaction> regularTx = std::make_unique<Transaction>(dummyInputs, dummyOutputs, txData);
        regularTx->txId = regularTx->calculateHash(rxContext); // Calcular el TxId para la dummy transaction
        blockTransactions.push_back(std::move(regularTx));
    }
    
    std::unique_ptr<Block> newBlock = std::make_unique<Block>(
        1, // Version
        prevHash,
        currentTimestamp,
        difficulty,
        std::move(blockTransactions) // Mover las transacciones al nuevo bloque
    );

    std::cout << "Minando Bloque #" << chain.size() << "..." << std::endl; // Usamos chain.size() para el número de bloque
    mineBlockInternal(*newBlock, rxContext);
    
    // El hash final del bloque se ha asignado dentro de mineBlockInternal
    std::cout << "Hash del bloque: " << toHexString(newBlock->header.blockHash) << std::endl;

    return newBlock;
}

// Añade un bloque minado a la cadena y realiza validaciones básicas
bool Blockchain::addBlock(std::unique_ptr<Block> block, RandomXContext& rxContext, const std::vector<std::string>& currentPendingTxData) {
    if (!block) {
        std::cerr << "Error: Intento de añadir un bloque nulo." << std::endl;
        return false;
    }

    if (chain.empty()) {
        std::cerr << "Error: No se puede añadir un bloque sin que el Bloque Genesis exista ya." << std::endl;
        return false;
    }

    const Block& lastBlock = getLastBlock();

    // 1. Verificar Previous Hash
    if (block->header.prevBlockHash != lastBlock.header.blockHash) {
        std::cerr << "Error: Previous Hash del bloque no coincide con el hash del ultimo bloque de la cadena." << std::endl;
        std::cerr << "  Expected: " << toHexString(lastBlock.header.blockHash) << std::endl;
        std::cerr << "  Got:      " << toHexString(block->header.prevBlockHash) << std::endl;
        return false;
    }

    // 2. Verificar Proof of Work (dificultad)
    // El hash del bloque ya debería estar en block->header.blockHash después de la minería
    if (!checkDifficulty(block->header.blockHash, block->header.difficultyTarget)) {
        std::cerr << "Error: El bloque no cumple con la dificultad requerida." << std::endl;
        std::cerr << "  Hash del bloque: " << toHexString(block->header.blockHash) << std::endl;
        std::cerr << "  Dificultad esperada (primer byte 0x00): 0x" << std::hex << std::setw(8) << std::setfill('0') << block->header.difficultyTarget << std::dec << std::endl;
        return false;
    }
    
    // 3. Verificar Merkle Root
    // Recalcular el Merkle Root del bloque y compararlo con el que trae el header
    std::vector<RandomXHash> txHashesForVerification;
    for (const auto& tx_ptr : block->transactions) {
        txHashesForVerification.push_back(tx_ptr->txId);
    }
    RandomXHash calculatedMerkleRoot;
    if (!txHashesForVerification.empty()) {
        if (txHashesForVerification.size() == 1) {
            calculatedMerkleRoot = txHashesForVerification[0];
        } else {
            std::vector<RandomXHash> tempHashes = txHashesForVerification;
            while (tempHashes.size() > 1) {
                if (tempHashes.size() % 2 != 0) {
                    tempHashes.push_back(tempHashes.back());
                }
                std::vector<RandomXHash> newLevel;
                for (size_t i = 0; i < tempHashes.size(); i += 2) {
                    std::vector<uint8_t> combined;
                    for (uint8_t byte : tempHashes[i]) combined.push_back(byte);
                    for (uint8_t byte : tempHashes[i+1]) combined.push_back(byte);
                    newLevel.push_back(rxContext.calculateHash(combined));
                }
                tempHashes = newLevel;
            }
            calculatedMerkleRoot = tempHashes[0];
        }
    } else {
        calculatedMerkleRoot.fill(0); // O el hash de un bloque vacío si es la regla
    }

    if (calculatedMerkleRoot != block->header.merkleRoot) {
        std::cerr << "Error: El Merkle Root del bloque es invalido." << std::endl;
        std::cerr << "  Calculado: " << toHexString(calculatedMerkleRoot) << std::endl;
        std::cerr << "  En header: " << toHexString(block->header.merkleRoot) << std::endl;
        return false;
    }

    // 4. (Simplificado por ahora) Validar Transacciones
    // Asegurarse de que haya al menos una transacción (la coinbase)
    if (block->transactions.empty()) {
        std::cerr << "Error: El bloque no contiene transacciones." << std::endl;
        return false;
    }

    // 5. Añadir el bloque a la cadena
    chain.push_back(std::move(block));
    std::cout << "Bloque #" << chain.size() -1 << " añadido a la cadena." << std::endl;
    return true;
}

const Block& Blockchain::getLastBlock() const {
    return *chain.back();
}

size_t Blockchain::getChainSize() const {
    return chain.size();
}

} // namespace Radix