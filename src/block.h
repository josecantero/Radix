// block.h
#ifndef BLOCK_H
#define BLOCK_H

#include <string>
#include <vector>
#include <cstdint> // Para uint64_t
#include <chrono>  // Para std::chrono::system_clock
#include <map>     // Para std::map en isValid

#include "transaction.h"
#include "randomx_util.h" // Para la declaración de RandomXContext

namespace Radix {

// Declaración anticipada para evitar dependencia circular si es necesario
// class RandomXContext; // No es necesario si randomx_util.h ya lo declara

class Block {
public:
    // Propiedades del bloque
    uint64_t version;
    long long timestamp;
    std::string prevHash;
    std::string merkleRoot;
    unsigned int difficulty;
    uint64_t nonce;
    std::string hash;
    std::vector<Transaction> transactions; // Lista de transacciones en este bloque

    // Constructor
    Block(uint64_t version, const std::string& prevHash, const std::vector<Transaction>& transactions,
          unsigned int difficulty, RandomXContext& rxContext_ref);

    // Calcula el hash del bloque usando RandomX
    std::string calculateHash() const;

    // Realiza la Prueba de Trabajo (Proof of Work)
    void mineBlock(unsigned int difficulty);

    // Convierte el bloque a una representación de cadena para impresión/depuración
    std::string toString() const;

    // Valida la integridad de un bloque (incluyendo sus transacciones)
    // Recibe una referencia al contexto de RandomX y el UTXO set actual para validación de transacciones
    bool isValid(RandomXContext& rxContext_ref, const std::map<std::string, TransactionOutput>& utxoSet) const;


private:
    // Referencia al contexto de RandomX para hashing
    RandomXContext& rxContext_;

    // Calcula la raíz de Merkle para las transacciones del bloque
    std::string calculateMerkleRoot() const;

    // Función auxiliar para construir el árbol de Merkle
    std::string buildMerkleTree(const std::vector<std::string>& hashes) const;
};

} // namespace Radix

#endif // BLOCK_H
