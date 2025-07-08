// block.h
#ifndef BLOCK_H
#define BLOCK_H

#include <string>
#include <vector>
#include <memory> // Para std::unique_ptr
#include <array>  // Para RandomXHash
#include <map>    // Para std::map en isValid

#include "transaction.h" // Incluir la clase Transaction
#include "randomx_util.h" // Para RandomXContext y RandomXHash

namespace Radix {

class Block {
public:
    // Constructor del bloque
    Block(int version, std::string prevHash, std::vector<Radix::Transaction> transactions, 
          unsigned int difficultyTarget, const RandomXContext& rxContext_ref); // Añadido rxContext_ref

    int version; // Versión del bloque
    long long timestamp; // Marca de tiempo de creación del bloque
    std::string prevHash; // Hash del bloque anterior en la cadena
    Radix::RandomXHash merkleRoot; // Raíz del árbol Merkle de transacciones
    unsigned int difficultyTarget; // Objetivo de dificultad para la minería
    long long nonce; // Valor numérico utilizado para encontrar el hash válido (prueba de trabajo)
    std::string hash; // Hash del bloque actual
    std::vector<Radix::Transaction> transactions; // Lista de transacciones incluidas en este bloque

    // Calcula el hash del encabezado del bloque.
    std::string calculateHash() const; // Ya no necesita rxContext como parámetro, usa la referencia miembro.
    // Mina el bloque (encuentra un nonce válido).
    void mineBlock(unsigned int difficulty); // Ya no necesita rxContext como parámetro, usa la referencia miembro.
    // Comprueba si el hash del bloque cumple con el objetivo de dificultad.
    bool checkDifficulty(unsigned int difficulty) const;
    // Valida la integridad del bloque (hashes, transacciones, etc.).
    // Ahora toma el UTXOSet para validar las transacciones.
    bool isValid(const std::map<std::string, TransactionOutput>& utxoSet) const; 
    // Convierte el bloque a una representación de cadena para visualización.
    std::string toString() const; // Ya no necesita rxContext como parámetro, usa la referencia miembro.

private:
    const RandomXContext& rxContext_; // Referencia al contexto RandomX

    // Actualiza la raíz de Merkle del bloque a partir de sus transacciones.
    void updateMerkleRoot(); 
};

} // namespace Radix

#endif // BLOCK_H
