// block.h
#ifndef BLOCK_H
#define BLOCK_H

#include <string>
#include <vector>
#include <cstdint> // Para uint64_t
#include <chrono>  // Para std::chrono::system_clock
#include <map>     // Para std::map en isValid
#include <fstream> // Para serialización binaria
#include <atomic>

#include "transaction.h"
#include "randomx_util.h" // Para la declaración de RandomXContext

namespace Radix {

// Declaración anticipada de las clases y utilidades de persistencia
namespace Persistence {
    // Declaraciones de funciones de serialización necesarias (para evitar incluir persistence_util.h)
    template <typename T> void writePrimitive(std::ostream& fs, const T& data);
    template <typename T> T readPrimitive(std::istream& fs);
    void writeString(std::ostream& fs, const std::string& str);
    std::string readString(std::istream& fs);
}

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

    // Constructor normal
    Block(uint64_t version, const std::string& prevHash, const std::vector<Transaction>& transactions,
          unsigned int difficulty, RandomXContext& rxContext_ref);

    // Constructor vacío para deserialización
    // Nota: La referencia rxContext_ debe ser inicializada en el constructor o manejada externamente.
    // Por simplicidad, se inicializa la referencia a una instancia temporal si no se usa para minar/validar
    // hasta que loadChain la reasigne, o se usa el constructor por defecto sin parámetros.
    // Aquí declaramos el constructor por defecto:
    Block(); 

    // Calcula el hash del bloque usando RandomX
    std::string calculateHash() const;

    // Realiza la Prueba de Trabajo (Proof of Work)
    void mineBlock(unsigned int difficulty, const std::atomic<bool>& running);

    // Convierte el bloque a una representación de cadena para impresión/depuración
    std::string toString() const;

    // Valida la integridad de un bloque (incluyendo sus transacciones)
    bool isValid(RandomXContext& rxContext_ref, const std::map<std::string, TransactionOutput>& utxoSet) const;

    // Métodos de Persistencia Binaria ¡NUEVO!
    void serialize(std::ostream& fs) const;
    void deserialize(std::istream& fs);


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