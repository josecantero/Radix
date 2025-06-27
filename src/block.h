// block.h
#ifndef BLOCK_H
#define BLOCK_H

#include <string>
#include <vector>
#include <memory> // Para std::unique_ptr
#include "transaction.h" // Incluir la clase Transaction (actualizada)
#include "randomx_util.h" // Para RandomXHash y RandomXContext

namespace Radix {

class Block {
public:
    int version; // Versión del bloque
    std::string prevHash; // Hash del bloque anterior en la cadena
    std::string merkleRoot; // Raíz de Merkle de las transacciones del bloque
    long long timestamp; // Marca de tiempo del bloque
    unsigned int difficultyTarget; // Objetivo de dificultad para la minería
    long long nonce; // Valor de prueba de trabajo
    std::string hash; // Hash del bloque actual
    std::vector<Transaction> transactions; // Transacciones contenidas en el bloque (cambiado a vector de objetos Transaction)

    // Constructor del bloque
    // Ahora toma una referencia constante al RandomXContext
    Block(int version, std::string prevHash, std::vector<Transaction> transactions, 
          unsigned int difficultyTarget, const RandomXContext& rxContext_ref);

    // Calcula el hash del encabezado del bloque utilizando el algoritmo RandomX.
    // Ya no necesita el rxContext como parámetro, usa la referencia miembro.
    std::string calculateHash() const;
    
    // Mina el bloque hasta que se encuentra un hash que cumpla con la dificultad.
    // Ya no necesita el rxContext como parámetro, usa la referencia miembro.
    void mineBlock(unsigned int difficulty);
    
    // Convierte el bloque a una representación de cadena para visualización.
    // Ya no necesita el rxContext como parámetro, usa la referencia miembro.
    std::string toString() const;
    
    // Valida la integridad del bloque (hashes, dificultad, transacciones).
    // Ya no necesita el rxContext como parámetro, usa la referencia miembro.
    bool isValid() const; 

private:
    const RandomXContext& rxContext_; // Referencia al contexto RandomX

    // Actualiza la raíz de Merkle basándose en las transacciones actuales del bloque.
    void updateMerkleRoot();
    // Comprueba si el hash del bloque cumple con el objetivo de dificultad.
    bool checkDifficulty(unsigned int difficulty) const;
};

} // namespace Radix

#endif // BLOCK_H
