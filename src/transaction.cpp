// transaction.cpp
#include "transaction.h"
#include "crypto.h" // Para Radix::KeyPair, Radix::SHA256, Radix::toHexString
#include "randomx_util.h" // Para toHexString
#include "money_util.h" // ¡NUEVO! Para formatRadsToRDX

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <algorithm> // Para std::all_of
#include <iomanip>   // Para std::fixed, std::setprecision, etc.
#include <chrono>    // Para std::chrono::system_clock
#include <array>     // Para asegurar la definición completa de std::array
#include <new>       // Para std::nothrow_t y sobrecargas de operator new
#include <cstddef>   // Para std::streamsize y otros tipos de definición estándar

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
Transaction::Transaction(const std::string& recipientAddress, uint64_t amount, bool isCoinbase)
    : isCoinbase(isCoinbase) {
    this->timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
    // Las coinbase no tienen inputs
    outputs.push_back(TransactionOutput(amount, recipientAddress));
    this->id = calculateHash(); // Calcula el ID de la transacción
}

// Calcula el hash crudo de la transacción (sin la firma)
std::string Transaction::calculateRawHash() const {
    std::stringstream ss;
    ss << timestamp;

    for (const auto& input : inputs) {
        ss << input.prevTxId << input.outputIndex;
        // La clave pública se incluye como bytes puros
        for (uint8_t byte : input.pubKey) {
            ss << byte;
        }
        // La firma NO se incluye, ya que se firma el hash de la transacción
        // sin la firma.
    }

    for (const auto& output : outputs) {
        ss << output.amount << output.recipientAddress;
    }
    
    // Incluir el estado de Coinbase
    ss << isCoinbase;

    return ss.str();
}

// Calcula el hash final de la transacción
std::string Transaction::calculateHash() const {
    return toHexString(Radix::SHA256(calculateRawHash()));
}

// Firma la transacción con la clave privada del remitente
void Transaction::sign(const PrivateKey& senderPrivateKey, const PublicKey& senderPublicKey, const std::map<std::string, TransactionOutput>& utxoSet) {
    if (isCoinbase) {
        return;
    }

    // 1. Obtener el hash crudo de la transacción (sin la firma)
    std::string rawHash = calculateRawHash();
    Radix::RandomXHash messageHash = Radix::SHA256(rawHash);

    // 2. Obtener el total de entradas y validar propiedad/existencia
    uint64_t totalInputAmount = 0;
    for (size_t i = 0; i < inputs.size(); ++i) {
        const auto& input = inputs[i];
        std::string utxoKey = input.prevTxId + ":" + std::to_string(input.outputIndex);
        
        // Verificar que la UTXO existe en el conjunto de UTXOs no gastadas
        auto it = utxoSet.find(utxoKey);
        if (it == utxoSet.end()) {
            throw std::runtime_error("Error de firma: La UTXO referenciada (" + utxoKey + ") no existe o ya ha sido gastada.");
        }

        const TransactionOutput& utxo = it->second;

        // Verificar que la clave pública de la entrada coincide con la clave pública esperada (el dueño de la UTXO)
        if (utxo.recipientAddress != KeyPair::deriveAddress(senderPublicKey)) {
             throw std::runtime_error("Error de firma: La clave pública proporcionada no es la dueña de la UTXO referenciada.");
        }

        // 3. Verificar que la clave pública en el input coincide con la clave pública que firma
        if (input.pubKey != senderPublicKey) {
            throw std::runtime_error("Error de firma: La clave pública en el input es inconsistente con la clave que firma.");
        }
        
        totalInputAmount += utxo.amount;
    }

    // 4. Verificar montos de salida
    uint64_t totalOutputAmount = 0;
    for (const auto& output : outputs) {
        totalOutputAmount += output.amount;
    }
    
    // 5. Validar que la salida total no exceda la entrada total
    if (totalOutputAmount > totalInputAmount) {
         throw std::runtime_error("Error de firma: La salida total (" + Radix::formatRadsToRDX(totalOutputAmount) + 
                                  ") excede la entrada total (" + Radix::formatRadsToRDX(totalInputAmount) + "). Transacción inválida.");
    }
    
    // 6. Generar la firma
    KeyPair keyPair(senderPrivateKey);
    Signature signature = keyPair.sign(messageHash);

    // 7. Aplicar la firma a todos los inputs
    for (auto& input : inputs) {
        input.signature = signature;
    }
    
    // Recalcular el ID de la transacción ya que ahora incluye la firma
    this->id = calculateHash();
}

// Valida la transacción (firmas, montos, UTXOs)
bool Transaction::isValid(const std::map<std::string, TransactionOutput>& utxoSet) const {
    // 1. Validación básica de la transacción
    if (id != calculateHash()) {
        std::cerr << "Error de validacion: ID de transaccion no coincide con el hash calculado." << std::endl;
        return false;
    }

    // 2. Transacciones Coinbase
    if (isCoinbase) {
        if (!inputs.empty() || outputs.empty()) {
            std::cerr << "Error de validacion: Transaccion Coinbase invalida (inputs=" << inputs.size() << ", outputs=" << outputs.size() << ")." << std::endl;
            return false;
        }
        return true;
    }

    // 3. Transacciones normales: deben tener inputs y outputs.
    if (inputs.empty() || outputs.empty()) {
        std::cerr << "Error de validacion: Transaccion normal invalida (inputs/outputs vacios)." << std::endl;
        return false;
    }

    // 4. Validación de firmas, propiedad de UTXO y montos
    uint64_t totalInputAmount = 0;
    uint64_t totalOutputAmount = 0;
    std::string expectedAddress; // Dirección del propietario que firma
    std::map<std::string, bool> spentUtxos; 

    for (const auto& input : inputs) {
        std::string utxoKey = input.prevTxId + ":" + std::to_string(input.outputIndex);

        // Doble gasto local
        if (spentUtxos.count(utxoKey)) {
             std::cerr << "Error de validacion: Doble gasto detectado dentro de la misma transaccion (" << utxoKey << ")." << std::endl;
             return false;
        }
        spentUtxos[utxoKey] = true;
        
        // UTXO existente
        auto it = utxoSet.find(utxoKey);
        if (it == utxoSet.end()) {
            std::cerr << "Error de validacion: La UTXO referenciada (" << utxoKey << ") no existe o ya ha sido gastada." << std::endl;
            return false;
        }
        const TransactionOutput& utxo = it->second;
        
        // Consistencia de la dirección
        if (expectedAddress.empty()) {
            expectedAddress = utxo.recipientAddress;
        } else if (expectedAddress != utxo.recipientAddress) {
            std::cerr << "Error de validacion: Multiples direcciones encontradas en inputs con una sola firma." << std::endl;
            return false;
        }

        // Validación de la Firma
        std::string rawHash = calculateRawHash();
        Radix::RandomXHash messageHash = Radix::SHA256(rawHash);
        
        if (input.pubKey.empty() || input.signature.empty() || utxo.recipientAddress != KeyPair::deriveAddress(input.pubKey)) {
            std::cerr << "Error de validacion: Clave publica o firma faltante/invalida para la UTXO: " << utxoKey << std::endl;
            return false;
        }

        if (!KeyPair::verify(input.pubKey, messageHash, input.signature)) {
            std::cerr << "Error de validacion: Firma invalida en el input para la UTXO: " << utxoKey << std::endl;
            return false;
        }

        totalInputAmount += utxo.amount;
    }

    // D. Montos de salida y tarifas
    for (const auto& output : outputs) {
        if (output.amount == 0) {
            std::cerr << "Error de validacion: Monto de salida de cero rads no permitido." << std::endl;
            return false;
        }
        totalOutputAmount += output.amount;
    }

    // La salida total no puede exceder la entrada total (la diferencia es la tarifa de transacción)
    if (totalOutputAmount > totalInputAmount) {
        std::cerr << "Error de validacion: Salida total (" << Radix::formatRadsToRDX(totalOutputAmount) << 
                     ") excede la entrada total (" << Radix::formatRadsToRDX(totalInputAmount) << 
                     "). Sobregiro detectado." << std::endl;
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
        // CORRECCIÓN CRÍTICA: Usar formatRadsToRDX en lugar de la impresión de double
        ss << prefix << "  Amount: " << Radix::formatRadsToRDX(output.amount) << " RDX\n"
           << prefix << "  Recipient: " << output.recipientAddress << "\n";
    }

    return ss.str();
}

} // namespace Radix