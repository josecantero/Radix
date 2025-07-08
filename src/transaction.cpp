// transaction.cpp
#include "transaction.h"
#include "crypto.h" // Para Radix::SHA256, Radix::KeyPair
#include "randomx_util.h" // Para Radix::toHexString, Radix::fromHexString, Radix::RandomXHash

#include <iostream>
#include <sstream>
#include <chrono>
#include <algorithm> // Para std::all_of
#include <numeric>   // Para std::accumulate
#include <stdexcept> // Para std::runtime_error

namespace Radix {

// Constructor Principal para el Modelo UTXO:
Transaction::Transaction(const std::vector<TransactionInput>& inputs, const std::vector<TransactionOutput>& outputs, bool isCoinbase)
    : isCoinbase(isCoinbase), inputs(inputs), outputs(outputs) {
    this->timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch()).count();
    updateId(); // Calculate ID after inputs/outputs are set
}

// Constructor para transacciones coinbase (solo un destinatario y monto, y es coinbase)
Transaction::Transaction(std::string recipientAddress, double amount, bool isCoinbase)
    : isCoinbase(isCoinbase) {
    this->timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch()).count();
    this->inputs = {}; // Coinbase transactions have no inputs
    this->outputs.push_back({amount, recipientAddress, ""}); // UTXO ID will be set during block processing
    updateId(); // Calculate ID after outputs are set
}

// Actualiza el ID de la transacción (basado en calculateHash).
void Transaction::updateId() {
    this->id = calculateHash();
}

// Calcula el hash de la transacción
std::string Transaction::calculateHash() const {
    std::stringstream ss;
    ss << timestamp << isCoinbase;

    // Incluir hashes de inputs en el cálculo del hash
    for (const auto& input : inputs) {
        ss << input.prevTxId << input.outputIndex << Radix::toHexString(input.pubKey);
        // NOTA: No incluir la firma del input en el hash de la transacción, ya que la firma depende del hash
    }

    // Incluir hashes de outputs en el cálculo del hash
    for (const auto& output : outputs) {
        ss << output.amount << output.recipientAddress;
    }

    std::string data_to_hash = ss.str();
    Radix::RandomXHash hash_bytes = Radix::SHA256(data_to_hash); 
    return Radix::toHexString(hash_bytes);
}

// Firma la transacción (actualiza el campo de firma)
void Transaction::sign(const Radix::KeyPair& keyPair) {
    if (isCoinbase) {
        std::cerr << "Advertencia: Intentando firmar una transaccion coinbase. Las transacciones coinbase no requieren firma estandar." << std::endl;
        return;
    }

    if (inputs.empty()) {
        throw std::runtime_error("Error al firmar: Transaccion sin inputs para firmar.");
    }

    // El hash a firmar es el hash de la transacción
    std::string transaction_hash_str = calculateHash();
    Radix::RandomXHash message_hash_bytes;
    Radix::fromHexString(transaction_hash_str, message_hash_bytes); // Convierte string a RandomXHash

    // Firma cada input de la transacción
    for (auto& input : inputs) {
        // Verifica que la clave pública del input coincida con la clave pública del KeyPair
        if (input.pubKey.empty() || keyPair.getPublicKey() != input.pubKey) {
            std::cerr << "DEBUG (sign): KeyPair Public Key: " << Radix::toHexString(keyPair.getPublicKey()) << std::endl;
            std::cerr << "DEBUG (sign): Input Public Key: " << Radix::toHexString(input.pubKey) << std::endl;
            throw std::runtime_error("Error al firmar: La clave publica del par de claves no coincide con la clave publica del input.");
        }
        input.signature = keyPair.sign(message_hash_bytes);
    }
}

// Verifica la validez de la transacción, utilizando el conjunto de UTXO disponible.
bool Transaction::isValid(const std::map<std::string, TransactionOutput>& utxoSet) const {
    std::cerr << "DEBUG (isValid): Validando transaccion ID: " << id << std::endl;
    std::cerr << "DEBUG (isValid): Is Coinbase: " << (isCoinbase ? "Yes" : "No") << std::endl;
    std::cerr << "DEBUG (isValid): Numero de Inputs: " << inputs.size() << std::endl;
    std::cerr << "DEBUG (isValid): Numero de Outputs: " << outputs.size() << std::endl;


    if (isCoinbase) {
        // Reglas de validación para transacciones coinbase
        if (!inputs.empty()) {
            std::cerr << "Error de validacion de coinbase: Las transacciones coinbase no deben tener inputs." << std::endl;
            return false;
        }
        if (outputs.empty()) {
            std::cerr << "Error de validacion de coinbase: Las transacciones coinbase deben tener al menos una salida." << std::endl;
            return false;
        }
        // Podrías añadir reglas de monto aquí (ej. la recompensa no excede un límite).
        return true; 
    }

    // Para transacciones estándar (no coinbase):
    if (inputs.empty()) {
        std::cerr << "Error de validacion: Transaccion no coinbase sin inputs." << std::endl;
        return false;
    }
    if (outputs.empty()) {
        std::cerr << "Error de validacion: Transaccion sin outputs." << std::endl;
        return false;
    }

    // 1. Verificar que el ID de la transacción sea correcto
    if (calculateHash() != id) {
        std::cerr << "Error de validacion: El ID de la transaccion no coincide con su hash calculado." << std::endl;
        return false;
    }

    double totalInputAmount = 0;
    // 2. Validar cada input
    std::cerr << "DEBUG (isValid): Procesando inputs (" << inputs.size() << ")..." << std::endl;
    for (const auto& input : inputs) {
        // a) Verificar que la UTXO referenciada existe en el UTXOSet
        std::string utxoKey = input.prevTxId + ":" + std::to_string(input.outputIndex);
        auto it = utxoSet.find(utxoKey);
        if (it == utxoSet.end()) {
            // ERROR ESPECÍFICO: UTXO no encontrada o ya gastada
            std::cerr << "Error de validacion: UTXO de entrada no encontrada o ya gastada: " << utxoKey << std::endl;
            return false;
        }
        const TransactionOutput& spentUtxo = it->second;
        std::cerr << "DEBUG (isValid): Input UTXO: " << utxoKey << ", Monto: " << spentUtxo.amount << ", Destinatario: " << spentUtxo.recipientAddress << std::endl;

        // b) Verificar que la clave pública del input coincide con la dirección del propietario de la UTXO
        if (Radix::KeyPair::deriveAddress(input.pubKey) != spentUtxo.recipientAddress) {
            std::cerr << "Error de validacion: La clave publica del input (" << Radix::KeyPair::deriveAddress(input.pubKey) << ") no coincide con el propietario de la UTXO gastada (" << spentUtxo.recipientAddress << ")." << std::endl;
            return false;
        }

        // c) Verificar la firma del input
        if (input.signature.empty()) {
            std::cerr << "Error de validacion: Firma ausente para el input." << std::endl;
            return false;
        }

        // Recalcular el hash de la transacción que fue firmado
        std::string transaction_hash_str = calculateHash();
        Radix::RandomXHash message_hash_bytes;
        Radix::fromHexString(transaction_hash_str, message_hash_bytes); // Convierte string a RandomXHash

        if (!Radix::KeyPair::verify(input.pubKey, message_hash_bytes, input.signature)) {
            std::cerr << "Error de validacion: Firma invalida para el input." << std::endl;
            return false;
        }
        totalInputAmount += spentUtxo.amount;
    }
    std::cerr << "DEBUG (isValid): Suma Total de Entradas: " << totalInputAmount << std::endl;


    double totalOutputAmount = 0;
    // 3. Sumar el total de las salidas
    std::cerr << "DEBUG (isValid): Procesando outputs (" << outputs.size() << ")..." << std::endl;
    for (const auto& output : outputs) {
        if (output.amount <= 0) {
            std::cerr << "Error de validacion: El monto de salida debe ser positivo." << std::endl;
            return false;
        }
        std::cerr << "DEBUG (isValid): Output: Monto: " << output.amount << ", Destinatario: " << output.recipientAddress << std::endl;
        totalOutputAmount += output.amount;
    }
    std::cerr << "DEBUG (isValid): Suma Total de Salidas: " << totalOutputAmount << std::endl;

    // 4. Verificar que el total de entradas es mayor o igual al total de salidas (la diferencia es la tarifa de transacción)
    // Se puede añadir una tarifa mínima aquí si es necesario.
    if (totalInputAmount < totalOutputAmount) {
        // ERROR ESPECÍFICO: Fondos insuficientes
        std::cerr << "Error de validacion: Fondos insuficientes. Entradas: " << totalInputAmount << ", Salidas: " << totalOutputAmount << std::endl;
        return false;
    }

    std::cerr << "DEBUG (isValid): Transaccion valida." << std::endl;
    return true; // La transacción es válida
}

// Convierte la transacción a una representación de cadena para visualización
std::string Transaction::toString() const {
    std::stringstream ss;
    ss << "  Tx ID: " << id << "\n";
    ss << "    Timestamp: " << timestamp << "\n";
    ss << "    Is Coinbase: " << (isCoinbase ? "Yes" : "No") << "\n";

    ss << "    Inputs (" << inputs.size() << "):\n";
    for (const auto& input : inputs) {
        ss << input.toString();
    }

    ss << "    Outputs (" << outputs.size() << "):\n";
    for (const auto& output : outputs) {
        ss << output.toString();
    }
    return ss.str();
}

} // namespace Radix
