#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <vector>
#include <string>
#include <array>
#include <memory> // Para std::unique_ptr

#include "randomx_util.h" // Para RandomXHash y Address
#include "crypto.h"       // Para PublicKey, Signature

namespace Radix {

using Rads = uint64_t;

// Tipo para el hash de transacción (mismo que RandomXHash)
using TxId = Radix::RandomXHash;

// Estructura para representar una entrada de transacción
struct TxInput {
    Radix::RandomXHash prevTxId; // Hash de la transacción anterior
    uint32_t outputIndex;        // Índice de la salida en la transacción anterior
    Radix::Signature signature;  // Firma del input (scriptSig en Bitcoin)
    Radix::PublicKey pubKey;     // Clave pública del firmante (¡asegúrate de que este sea el nombre!)

    std::string toString() const;
};

// Estructura para representar una salida de transacción
struct TxOutput {
    uint64_t amount;           // Cantidad de unidades (ej. satoshis)
    Radix::Address recipientAddress; // Dirección del destinatario

    std::string toString() const;
};

// Clase principal para una transacción
class Transaction {
public:
    // Constructor general para transacciones normales
    Transaction(const std::vector<TxInput>& inputs, const std::vector<TxOutput>& outputs, Radix::RandomXContext& rxContext);

    // Constructor específico para transacciones Coinbase
    Transaction(const std::vector<TxOutput>& outputs, Radix::RandomXContext& rxContext);

    // Constructor por defecto (necesario si hay otros constructores)
    Transaction() = default; 

    // Métodos para obtener datos
    const TxId& getTxId() const { return txId; }
    const std::vector<TxInput>& getInputs() const { return inputs; }
    const std::vector<TxOutput>& getOutputs() const { return outputs; }
    bool isCoinbaseTransaction() const { return isCoinbase; } 

    // Cálculo del ID de la transacción (hash de la transacción)
    void calculateTxId(Radix::RandomXContext& rxContext);

    // Serialización para imprimir y hashear
    std::string toString() const;

    // Verificación de firmas
    bool verifySignatures(Radix::RandomXContext& rxContext) const;

private:
    TxId txId;
    std::vector<TxInput> inputs;
    std::vector<TxOutput> outputs;
    bool isCoinbase; // Añadir este miembro

};

} // namespace Radix

#endif // TRANSACTION_H