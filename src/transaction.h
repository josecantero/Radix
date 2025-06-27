// transaction.h
#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <string>
#include <vector>
#include <memory>
#include "crypto.h" // Para Radix::Signature y Radix::PublicKey
#include "randomx_util.h" // Para Radix::RandomXHash

namespace Radix {

// Representa una salida de transacción (cantidad y dirección del destinatario).
struct TransactionOutput {
    long long amount; // Cantidad de la criptomoneda
    std::string recipientAddress; // Dirección del destinatario

    // Serialización para hashing: convierte la salida a una cadena para calcular su hash.
    std::string serialize() const {
        return std::to_string(amount) + recipientAddress;
    }
};

// Representa una entrada de transacción.
struct TransactionInput {
    std::string prevTxId; // ID de la transacción anterior de la que se gasta la salida
    int outputIndex;      // Índice de la salida en prevTxId que se está gastando
    Radix::Signature signature; // La firma ECDSA del hash de la transacción
    Radix::PublicKey pubKey;    // La clave pública del remitente (para verificación)

    // Serialización para hashing: convierte la entrada a una cadena para calcular su hash.
    // Importante: No incluye la firma ni la clave pública, ya que estas son parte de la prueba
    // y no del contenido intrínseco de la transacción para su ID.
    std::string serializeForHash() const {
        return prevTxId + std::to_string(outputIndex);
    }
};

class Transaction {
public:
    std::string id; // ID de la transacción (hash de los datos de la transacción)
    bool isCoinbase; // true si es una transacción de coinbase (minería)
    std::vector<TransactionInput> inputs; // Entradas de la transacción
    std::vector<TransactionOutput> outputs; // Salidas de la transacción
    long long timestamp; // Marca de tiempo de la transacción

    // Constructor para una transacción de coinbase (sin entradas, solo recompensa)
    Transaction(bool isCoinbase = false);
    // Constructor completo para inicializar una transacción
    Transaction(std::string id, bool isCoinbase, std::vector<TransactionInput> inputs, std::vector<TransactionOutput> outputs, long long timestamp);

    // Calcula el hash de la transacción. Este es el TxID.
    std::string calculateHash() const;
    // Calcula el hash de los datos de la transacción que necesitan ser firmados.
    // Típicamente, es el mismo que calculateHash(), pero se distingue para claridad.
    Radix::RandomXHash getHashForSignature() const;

    // Firma todas las entradas de la transacción utilizando el par de claves proporcionado por el remitente.
    // En un escenario real, cada entrada podría tener un remitente diferente, requiriendo múltiples firmas.
    // Para simplificar, asumimos un solo firmante para todas las entradas por ahora.
    void sign(const Radix::KeyPair& signerKeys);

    // Verifica todas las firmas en las entradas de la transacción.
    bool isValid() const;

    // Convierte la transacción a una representación de cadena para registro/visualización.
    std::string toString() const;

    // Actualiza el ID de la transacción calculando su hash.
    // CAMBIO: Ahora es público para permitir el recálculo explícito si los outputs se añaden post-construcción.
    void updateId(); 
};

} // namespace Radix

#endif // TRANSACTION_H
