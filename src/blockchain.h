#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <vector>
#include <string>
#include <memory> // Para std::unique_ptr
#include <map>    // Para el balance de cuentas (si se implementa)

#include "block.h"        // Incluir la definición de Block
#include "transaction.h"  // Incluir la definición de Transaction
#include "randomx_util.h" // Incluir RandomXContext

namespace Radix {

// Se define el tipo UTXOSet para mayor claridad
// Mapea un "utxoId" (TxId:OutputIndex) a la TransactionOutput correspondiente
using UTXOSet = std::map<std::string, TransactionOutput>;

class Blockchain {
public:
    // Constructor de la Blockchain
    // Se requiere la dificultad al inicializar
    Blockchain(unsigned int difficulty, Radix::RandomXContext& rxContext_ref);

    // Añade una transacción a las transacciones pendientes
    // Ahora realizará una validación preliminar de UTXO.
    void addTransaction(const Radix::Transaction& transaction);

    // Mina las transacciones pendientes y crea un nuevo bloque
    // Actualizará el UTXOSet al añadir el nuevo bloque.
    void minePendingTransactions(const std::string& miningRewardAddress);

    // Obtiene el balance de una dirección específica utilizando el UTXOSet.
    double getBalanceOfAddress(const std::string& address) const;

    // Valida la integridad de toda la cadena, reconstruyendo el UTXOSet en el proceso.
    bool isChainValid() const;

    // Imprime todos los bloques en la cadena
    void printChain() const;

    // Obtiene el último bloque de la cadena
    const Block& getLatestBlock() const;

    // Nuevo método: Obtiene el tamaño actual de la cadena (número de bloques)
    size_t getChainSize() const;

private:
    std::vector<Block> chain;
    std::vector<Transaction> pendingTransactions;
    unsigned int difficulty;
    double miningReward;
    const Radix::RandomXContext& rxContext_; // Referencia al contexto RandomX

    // Conjunto de UTXO (Unspent Transaction Outputs)
    // Mapea un identificador de UTXO (TxID:OutputIndex) a la TransactionOutput.
    UTXOSet utxoSet; 

    // Crea el bloque génesis
    Block createGenesisBlock();

    // Aplica las transacciones de un bloque al UTXOSet, actualizando su estado.
    // Retorna true si la aplicación fue exitosa, false si hubo un doble gasto o UTXO inválida.
    bool applyBlockToUTXOSet(const Block& block, UTXOSet& currentUtxoSet) const;
};

} // namespace Radix

#endif // BLOCKCHAIN_H