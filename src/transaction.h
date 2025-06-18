#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <cstdint>
#include <string>
#include <vector>
#include "randomx_util.h" // Usaremos RandomXHash para el TxID

namespace Radix {

// Tipo para representar un TxID (Transaction ID), que es el hash de la transacción
using TxId = RandomXHash;

// Clase muy simplificada de una transacción para esta etapa
class Transaction {
public:
    TxId txId; // Hash de esta transacción
    std::string data; // Datos arbitrarios (placeholder para inputs/outputs/scripts)
    uint32_t timestamp; // Marca de tiempo de la transacción

    Transaction();
    Transaction(const std::string& _data);

    // Calcula el hash de la transacción (TxId)
    // Para simplificar, usaremos SHA256 o similar para el TxID, no RandomX.
    // RandomX es para PoW. SHA256 para hashing de datos y IDs.
    // Necesitaremos una función SHA256 en randomx_util o crear una nueva.
    // Por ahora, usaremos RandomXContext solo para simular un hashing.
    // Lo ideal es tener un hasher SHA256 para IDs y Merkle.
    TxId calculateHash(RandomXContext& rxContext) const; // Usaremos rxContext temporalmente para el hashing de Tx
                                                          // Pero lo ideal sería SHA256 para esto.

    // Serializa la transacción a un vector de bytes para hashing
    std::vector<uint8_t> serialize() const;

    std::string toString() const;
};

// Transacción Coinbase (especial para la recompensa del minero)
class CoinbaseTransaction : public Transaction {
public:
    uint64_t value; // Valor de la recompensa
    std::string coinbaseData; // Datos arbitrarios del minero

    CoinbaseTransaction(uint64_t value, const std::string& coinbaseData);

    std::vector<uint8_t> serialize() const;
    TxId calculateHash(RandomXContext& rxContext) const; // Igual, temporalmente con RandomXContext
    std::string toString() const;
};


} // namespace Radix

#endif // TRANSACTION_H