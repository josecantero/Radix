// blockchain.h
#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <vector>
#include <string>
#include <memory> // Para std::unique_ptr
#include <map>    // Para el UTXOSet

#include "block.h"        // Incluir la definición de Block
#include "transaction.h"  // Incluir la definición de Transaction
#include "randomx_util.h" // Incluir RandomXContext

namespace Radix {

class Blockchain {
public:
    // Constructor de la Blockchain
    Blockchain(unsigned int difficulty, Radix::RandomXContext& rxContext_ref);

    // Añade una transacción a las transacciones pendientes
    void addTransaction(const Radix::Transaction& transaction);

    // Mina las transacciones pendientes y crea un nuevo bloque
    void minePendingTransactions(const std::string& miningRewardAddress);

    // Obtiene el balance de una dirección específica utilizando el UTXOSet
    double getBalanceOfAddress(const std::string& address) const;

    // Nuevo método para obtener las UTXOs de una dirección específica
    std::vector<TransactionOutput> getUTXOsForAddress(const std::string& address) const;

    // Valida la integridad de toda la cadena
    bool isChainValid() const;

    // Imprime todos los bloques en la cadena
    void printChain() const;

    // Obtiene el último bloque de la cadena
    const Block& getLatestBlock() const;

    // Obtiene el tamaño actual de la cadena (número de bloques)
    size_t getChainSize() const;

    // Obtiene el UTXOSet actual (para depuración o validación externa)
    const std::map<std::string, TransactionOutput>& getUTXOSet() const { return utxoSet; }

private:
    std::vector<Block> chain;
    std::vector<Transaction> pendingTransactions;
    unsigned int difficulty;
    double miningReward;
    const Radix::RandomXContext& rxContext_; // Referencia al contexto RandomX

    std::map<std::string, TransactionOutput> utxoSet; // Conjunto de UTXOs (Unspent Transaction Outputs)

    // Crea el bloque génesis
    Block createGenesisBlock();
    
    // Helper para procesar transacciones de un bloque y actualizar un UTXOSet dado.
    // Se usa en minePendingTransactions (para utxoSet miembro) y en isChainValid (para utxoSet simulado).
    static void applyBlockTransactionsToUtxoSet(const Block& block, std::map<std::string, TransactionOutput>& targetUtxoSet);
};

} // namespace Radix

#endif // BLOCKCHAIN_H
