// transaction.h
#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <string>
#include <vector>
#include <map> // Para std::map en isValid
#include <cstdint> // Para uint64_t
#include <iostream> // Para serialización

#include "crypto.h" // Para Radix::PublicKey, Radix::Signature, Radix::RandomXHash

namespace Radix {

// Declaración anticipada de las clases y utilidades de persistencia
namespace Persistence {
    // Declaraciones de funciones de serialización necesarias (para evitar incluir persistence_util.h)
    // Declaraciones de funciones de serialización necesarias (para evitar incluir persistence_util.h)
    template <typename T> void writePrimitive(std::ostream& fs, const T& data);
    template <typename T> T readPrimitive(std::istream& fs);
    void writeString(std::ostream& fs, const std::string& str);
    std::string readString(std::istream& fs);
    void writeVector(std::ostream& fs, const std::vector<uint8_t>& vec);
    std::vector<uint8_t> readVector(std::istream& fs);
}

// Estructuras para las entradas y salidas de transacciones
struct TransactionInput {
    std::string prevTxId;    // ID de la transacción anterior de la cual se gasta una salida
    uint64_t outputIndex;    // Índice de la salida en la transacción anterior
    PublicKey pubKey;        // Clave pública del firmante (para verificar la firma)
    Signature signature;     // Firma de la transacción

    // Constructor por defecto
    TransactionInput() : outputIndex(0) {}

    // Constructor con parámetros
    TransactionInput(const std::string& prevTxId, uint64_t outputIndex, const PublicKey& pubKey, const Signature& signature)
        : prevTxId(prevTxId), outputIndex(outputIndex), pubKey(pubKey), signature(signature) {}
    
    // Métodos de Persistencia Binaria
    void serialize(std::ostream& fs) const;
    void deserialize(std::istream& fs);
};

struct TransactionOutput {
    uint64_t amount;          // Cantidad de monedas (en rads)
    std::string recipientAddress; // Dirección del destinatario

    // Constructor por defecto
    TransactionOutput() : amount(0ULL) {} // Inicializar a 0ULL

    // Constructor con parámetros
    TransactionOutput(uint64_t amount, const std::string& recipientAddress)
        : amount(amount), recipientAddress(recipientAddress) {}

    // Métodos de Persistencia Binaria
    void serialize(std::ostream& fs) const;
    void deserialize(std::istream& fs);
};

class Transaction {
public:
    std::string id;             // Hash de la transacción
    long long timestamp;        // Marca de tiempo de la transacción
    std::vector<TransactionInput> inputs;   // Entradas de la transacción
    std::vector<TransactionOutput> outputs; // Salidas de la transacción
    bool isCoinbase;            // Indica si es una transacción coinbase

    // Constructor para transacciones normales
    Transaction(const std::vector<TransactionInput>& inputs, const std::vector<TransactionOutput>& outputs);
    // Constructor vacío para deserialización
    Transaction() : timestamp(0), isCoinbase(false) {}

    // Constructor para transacciones coinbase
    Transaction(const std::string& recipientAddress, uint64_t amount, bool isCoinbase = true);

    // Calcula el hash de la transacción
    std::string calculateHash() const;

    // Firma la transacción con la clave privada del remitente
    void sign(const PrivateKey& senderPrivateKey, const PublicKey& senderPublicKey, const std::map<std::string, TransactionOutput>& utxoSet);

    // Valida la transacción (firmas, montos, UTXOs)
    bool isValid(const std::map<std::string, TransactionOutput>& utxoSet) const;

    // Convierte la transacción a una representación de cadena para impresión/depuración
    std::string toString(bool indent = false) const;

    // Métodos de Persistencia Binaria
    void serialize(std::ostream& fs) const;
    void deserialize(std::istream& fs);

private:
    // Método auxiliar para calcular el hash de la transacción
    std::string calculateRawHash() const;
};

} // namespace Radix

#endif // TRANSACTION_H