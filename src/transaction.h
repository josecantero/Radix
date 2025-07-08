// transaction.h
#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <string>
#include <vector>
#include <cstdint> // Para uint8_t
#include <memory> // Para std::unique_ptr si fuera necesario
#include <sstream> // Para std::stringstream en toString
#include <map>     // Para std::map en Transaction::isValid (para el UTXOSet)

#include "crypto.h"       // Para Radix::PublicKey, Radix::Signature, Radix::Address, Radix::KeyPair
#include "randomx_util.h" // Para Radix::RandomXHash, Radix::toHexString, Radix::fromHexString

namespace Radix {

// Struct para representar una entrada de transacción (referencia a una salida anterior)
struct TransactionInput {
    std::string prevTxId;    // ID de la transacción anterior de la que se gasta la salida
    int outputIndex;         // Índice de la salida en la prevTxId que se está gastando
    Radix::Signature signature; // Firma que autoriza el gasto de esta entrada
    Radix::PublicKey pubKey;     // Clave pública del propietario de la salida gastada

    // Método para convertir la entrada a una cadena legible
    std::string toString() const {
        std::stringstream ss;
        ss << "      PrevTxId: " << prevTxId << "\n";
        ss << "      OutputIndex: " << outputIndex << "\n";
        ss << "      PubKey: " << Radix::toHexString(pubKey) << "\n";
        ss << "      Signature: " << Radix::toHexString(signature) << "\n";
        return ss.str();
    }
};

// Struct para representar una salida de transacción (a quién va el monto)
struct TransactionOutput {
    double amount;
    std::string recipientAddress;
    std::string utxoId; // Identificador único para esta UTXO (TxId:OutputIndex)

    // Método para convertir la salida a una cadena legible
    std::string toString() const {
        std::stringstream ss;
        ss << "      Amount: " << amount << "\n";
        ss << "      Recipient: " << recipientAddress << "\n";
        ss << "      UTXO ID: " << utxoId << "\n"; 
        return ss.str();
    }
};

class Transaction {
public:
    // **NUEVO Constructor Principal para el Modelo UTXO:**
    // Una transacción se define por sus entradas y salidas.
    Transaction(const std::vector<TransactionInput>& inputs, const std::vector<TransactionOutput>& outputs, bool isCoinbase = false);

    // Constructor para transacciones coinbase (solo un destinatario y monto, y es coinbase)
    // Este constructor simplificado es para la creación de la recompensa del minero.
    Transaction(std::string recipientAddress, double amount, bool isCoinbase = true);

    // --- Miembros de la transacción ---
    std::string id; // ID de la transacción (hash de los datos de la transacción)
    long long timestamp; // Marca de tiempo de la transacción
    bool isCoinbase; // Indica si es una transacción de coinbase

    std::vector<TransactionInput> inputs; // Entradas de la transacción
    std::vector<TransactionOutput> outputs; // Salidas de la transacción

    // NOTA: senderAddress y senderPubKey ahora se derivan de los inputs
    // y se usan internamente para la lógica de firma/validación.
    // No son miembros directos que se inicialicen desde el constructor principal
    // para evitar redundancia y mantener el modelo UTXO puro.

    // --- Métodos de la transacción ---
    // Calcula el hash de la transacción (TxID).
    std::string calculateHash() const;

    // Firma la transacción.
    // En un modelo UTXO, esto implica firmar el hash de la transacción y
    // asignar la clave pública y la firma a cada input.
    void sign(const Radix::KeyPair& keyPair);

    // Verifica la validez de la transacción, utilizando el conjunto de UTXO disponible.
    // Este método es crucial para la validación del doble gasto y la validez de los fondos.
    // Recibe el UTXOSet actual para verificar las entradas.
    bool isValid(const std::map<std::string, TransactionOutput>& utxoSet) const;

    // Convierte la transacción a una representación de cadena para visualización.
    std::string toString() const;

private:
    // Actualiza el ID de la transacción (basado en calculateHash).
    // Es privado porque el ID debe ser gestionado internamente después de la construcción.
    void updateId();
};

} // namespace Radix

#endif // TRANSACTION_H
