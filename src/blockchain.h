// blockchain.h
#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <vector>
#include <string>
#include <map>    // Para el UTXOSet
#include <fstream>  // Para la gestión de archivos (persistenca)

#include "block.h"        // Incluir la definición de Block
#include "transaction.h"  // Incluir la definición de Transaction
#include "randomx_util.h" // Incluir RandomXContext

namespace Radix {

// Define el intervalo de bloques para el halving (para demostración, un número pequeño)
// En Bitcoin, esto es 210,000 bloques.
const unsigned int HALVING_INTERVAL = 3; 

class Blockchain {
public:
    // Constructor de la Blockchain
    // Se requiere la dificultad al inicializar
    Blockchain(unsigned int difficulty, Radix::RandomXContext& rxContext_ref);

    // Añade una transacción a las transacciones pendientes
    // Ahora valida la transacción contra el UTXOSet actual
    void addTransaction(const Radix::Transaction& transaction);

    // Mina las transacciones pendientes y crea un nuevo bloque
    // Ahora recibe el RandomXContext
    void minePendingTransactions(const std::string& miningRewardAddress);

    // Obtiene el balance de una dirección específica utilizando el UTXOSet
    uint64_t getBalanceOfAddress(const std::string& address) const;

    // Valida la integridad de toda la cadena
    // Ahora recibe el RandomXContext para la validación de bloques
    bool isChainValid() const;

    // Imprime todos los bloques en la cadena
    void printChain() const;

    // Obtiene el último bloque de la cadena
    const Block& getLatestBlock() const;

    // Nuevo método: Obtiene el tamaño actual de la cadena (número de bloques)
    size_t getChainSize() const;

    // Getter público para el UTXO Set
    const std::map<std::string, TransactionOutput>& getUtxoSet() const { return utxoSet; }

    // ----------------------------------------------------------------------
    // MÉTODOS DE PERSISTENCIA BINARIA ¡NUEVO!
    // ----------------------------------------------------------------------
    // Guarda la cadena de bloques en un archivo binario.
    void saveChain(const std::string& filename) const;
    
    // Carga la cadena de bloques desde un archivo binario y reconstruye el UTXO Set.
    // Retorna true si la carga fue exitosa y la cadena es válida.
    bool loadChain(const std::string& filename);


private:
    std::vector<Block> chain;
    std::vector<Transaction> pendingTransactions;
    unsigned int difficulty;
    uint64_t currentMiningReward; // Recompensa de minería actual (para el halving)
    Radix::RandomXContext& rxContext_; // Referencia al contexto RandomX
    std::map<std::string, TransactionOutput> utxoSet; // Conjunto de UTXO globales

    // Crea el bloque génesis
    Block createGenesisBlock();
    // Actualiza el UTXOSet con las transacciones de un nuevo bloque
    void updateUtxoSet(const Block& block);
    // Reinicia el UTXOSet y lo reconstruye a partir de la cadena actual
    void rebuildUtxoSet();
};

} // namespace Radix

#endif // BLOCKCHAIN_H