// transaction.cpp
#include "transaction.h"
#include "crypto.h" // Para Radix::KeyPair, Radix::SHA256, Radix::toHexString
#include "randomx_util.h" // Para toHexString
// #include "base58.h" // Se incluye si es necesario, pero no directamente en la lógica de Transaction

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <algorithm> // Para std::all_of
#include <iomanip>   // Para std::fixed, std::setprecision
#include <chrono>    // Para std::chrono::system_clock
#include <array>     // ¡NUEVO! Para asegurar la definición completa de std::array
#include <new>       // ¡NUEVO! Para std::nothrow_t y sobrecargas de operator new
#include <cstddef>   // ¡NUEVO! Para std::streamsize y otros tipos de definición estándar

namespace Radix {

// Constructor para transacciones normales
Transaction::Transaction(const std::vector<TransactionInput>& inputs, const std::vector<TransactionOutput>& outputs)
    : inputs(inputs), outputs(outputs), isCoinbase(false) {
    this->timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
    this->id = calculateHash(); // Calcula el ID de la transacción
}

// Constructor para transacciones coinbase
Transaction::Transaction(const std::string& recipientAddress, double amount, bool isCoinbase)
    : isCoinbase(isCoinbase) {
    this->timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
    // Las coinbase no tienen inputs
    outputs.push_back(TransactionOutput(amount, recipientAddress));
    this->id = calculateHash(); // Calcula el ID de la transacción
}

// Calcula el hash de la transacción
std::string Transaction::calculateHash() const {
    return calculateRawHash();
}

// Método auxiliar para calcular el hash de la transacción
std::string Transaction::calculateRawHash() const {
    std::stringstream ss;
    ss << timestamp;
    for (const auto& input : inputs) {
        ss << input.prevTxId << input.outputIndex << toHexString(input.pubKey) << toHexString(input.signature);
    }
    for (const auto& output : outputs) {
        ss << output.amount << output.recipientAddress;
    }
    ss << isCoinbase; // Incluir el estado coinbase en el hash

    // Usa SHA256 para el hash de la transacción
    return toHexString(Radix::SHA256(ss.str()));
}

// Firma la transacción con la clave privada del remitente
void Transaction::sign(const PrivateKey& senderPrivateKey, const PublicKey& senderPublicKey, const std::map<std::string, TransactionOutput>& utxoSet) {
    if (isCoinbase) {
        throw std::runtime_error("No se puede firmar una transaccion coinbase.");
    }

    // Verificar que las entradas de la transacción pertenecen al remitente
    double inputSum = 0;
    for (size_t i = 0; i < inputs.size(); ++i) {
        std::string utxoKey = inputs[i].prevTxId + ":" + std::to_string(inputs[i].outputIndex);
        auto it = utxoSet.find(utxoKey);
        if (it == utxoSet.end()) {
            throw std::runtime_error("UTXO de entrada no encontrada o ya gastada: " + utxoKey);
        }
        if (it->second.recipientAddress != KeyPair::deriveAddress(senderPublicKey)) {
            throw std::runtime_error("UTXO de entrada no pertenece al remitente.");
        }
        inputSum += it->second.amount;
    }

    // Verificar que la suma de outputs no excede la suma de inputs
    double outputSum = 0;
    for (const auto& output : outputs) {
        outputSum += output.amount;
    }

    if (outputSum > inputSum) {
        throw std::runtime_error("La suma de las salidas excede la suma de las entradas.");
    }

    // Crear un KeyPair temporal para firmar
    KeyPair signer(senderPrivateKey);

    // Hash de la transacción sin las firmas (para firmar)
    std::string hashToSign;
    {
        std::stringstream ss;
        ss << timestamp;
        for (const auto& input : inputs) {
            ss << input.prevTxId << input.outputIndex << toHexString(input.pubKey); // No incluir la firma
        }
        for (const auto& output : outputs) {
            ss << output.amount << output.recipientAddress;
        }
        ss << isCoinbase;
        hashToSign = toHexString(Radix::SHA256(ss.str()));
    }

    // Firmar cada input
    for (size_t i = 0; i < inputs.size(); ++i) {
        // Asegurarse de que la clave pública en el input coincida con la clave pública del firmante
        if (inputs[i].pubKey != senderPublicKey) {
            throw std::runtime_error("La clave publica en el input no coincide con la clave publica del firmante.");
        }
        inputs[i].signature = signer.sign(Radix::SHA256(hashToSign)); // Firmar el hash de la transacción
    }

    this->id = calculateHash(); // Recalcular el ID con las firmas
}

// Valida la transacción (firmas, montos, UTXOs)
bool Transaction::isValid(const std::map<std::string, TransactionOutput>& utxoSet) const {
    if (isCoinbase) {
        // Las transacciones coinbase no tienen inputs y crean una nueva moneda.
        // Solo verificamos que tenga al menos una salida y que el monto no sea negativo.
        return !outputs.empty() && outputs[0].amount >= 0;
    }

    if (inputs.empty()) {
        std::cerr << "Error de validacion: Transaccion no coinbase sin inputs." << std::endl;
        return false;
    }

    // Verificar que todas las entradas tienen firmas y claves públicas
    if (!std::all_of(inputs.begin(), inputs.end(), [](const TransactionInput& input){
        return !input.pubKey.empty() && !input.signature.empty();
    })) {
        std::cerr << "Error de validacion: Inputs de transaccion sin clave publica o firma." << std::endl;
        return false;
    }

    double inputSum = 0;
    for (const auto& input : inputs) {
        std::string utxoKey = input.prevTxId + ":" + std::to_string(input.outputIndex);
        auto it = utxoSet.find(utxoKey);

        if (it == utxoSet.end()) {
            std::cerr << "Error de validacion: UTXO de entrada no encontrada o ya gastada: " << utxoKey << std::endl;
            return false;
        }

        const TransactionOutput& referencedOutput = it->second;

        // Verificar que la clave pública del input coincide con la dirección de la UTXO referenciada
        if (KeyPair::deriveAddress(input.pubKey) != referencedOutput.recipientAddress) {
            std::cerr << "Error de validacion: La clave publica del input no coincide con el destinatario de la UTXO referenciada." << std::endl;
            return false;
        }

        // Hash de la transacción sin las firmas (para verificar)
        std::string hashToVerify;
        {
            std::stringstream ss;
            ss << timestamp;
            for (const auto& in : inputs) {
                ss << in.prevTxId << in.outputIndex << toHexString(in.pubKey); // No incluir la firma
            }
            for (const auto& out : outputs) {
                ss << out.amount << out.recipientAddress;
            }
            ss << isCoinbase;
            hashToVerify = toHexString(Radix::SHA256(ss.str()));
        }

        // Verificar la firma
        if (!KeyPair::verify(input.pubKey, Radix::SHA256(hashToVerify), input.signature)) {
            std::cerr << "Error de validacion: Firma invalida para el input de transaccion." << std::endl;
            return false;
        }
        inputSum += referencedOutput.amount;
    }

    double outputSum = 0;
    for (const auto& output : outputs) {
        if (output.amount < 0) {
            std::cerr << "Error de validacion: Output de transaccion con monto negativo." << std::endl;
            return false;
        }
        outputSum += output.amount;
    }

    // La suma de las salidas no puede exceder la suma de las entradas (incluyendo tarifas de transacción)
    if (outputSum > inputSum) {
        std::cerr << "Error de validacion: La suma de las salidas excede la suma de las entradas." << std::endl;
        return false;
    }

    // Si la transacción ya tiene un ID, verificar que coincide con el hash calculado
    if (!id.empty() && id != calculateRawHash()) {
        std::cerr << "Error de validacion: ID de transaccion no coincide con el hash calculado." << std::endl;
        return false;
    }

    std::cout << "DEBUG (isValid): Transaccion valida." << std::endl;
    return true;
}

// Convierte la transacción a una representación de cadena para impresión/depuración
std::string Transaction::toString(bool indent) const {
    std::string prefix = indent ? "    " : ""; // Cuatro espacios para indentación
    std::stringstream ss;
    ss << prefix << "Tx ID: " << id << "\n"
       << prefix << "Timestamp: " << timestamp << "\n"
       << prefix << "Is Coinbase: " << (isCoinbase ? "Yes" : "No") << "\n";

    ss << prefix << "Inputs (" << inputs.size() << "):\n";
    for (const auto& input : inputs) {
        ss << prefix << "  PrevTxId: " << input.prevTxId << "\n"
           << prefix << "  OutputIndex: " << input.outputIndex << "\n"
           << prefix << "  PubKey: " << toHexString(input.pubKey) << "\n"
           << prefix << "  Signature: " << toHexString(input.signature) << "\n";
    }

    ss << prefix << "Outputs (" << outputs.size() << "):\n";
    for (const auto& output : outputs) {
        ss << prefix << "  Amount: " << std::fixed << std::setprecision(0) << output.amount << "\n"
           << prefix << "  Recipient: " << output.recipientAddress << "\n"
           << prefix << "  UTXO ID: " << "\n"; // UTXO ID se genera dinámicamente, no es parte del output en sí
    }
    return ss.str();
}

} // namespace Radix
