// transaction.cpp
#include "transaction.h"
#include "crypto.h" // Para Radix::SHA256, Radix::KeyPair
#include "randomx_util.h" // Para Radix::toHexString, Radix::RandomXHash, Radix::fromHexString

#include <iostream>
#include <sstream> // Para stringstream
#include <chrono> // Para timestamp
#include <algorithm> // Para std::all_of
#include <numeric>   // Para std::accumulate

namespace Radix {

// Constructor para transacciones estándar (basado en inputs y outputs)
Transaction::Transaction(const std::vector<TransactionInput>& inputs, const std::vector<TransactionOutput>& outputs, bool isCoinbase)
    : inputs(inputs), outputs(outputs), isCoinbase(isCoinbase) {
    this->timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch()).count();
    updateId(); // Calcula el ID de la transacción al construirla.

    // Generar utxoId para cada nueva salida
    for (size_t i = 0; i < this->outputs.size(); ++i) {
        this->outputs[i].utxoId = this->id + ":" + std::to_string(i);
    }
}

// Constructor para transacciones coinbase (solo un destinatario y monto)
Transaction::Transaction(std::string recipientAddress, double amount, bool isCoinbase)
    : isCoinbase(isCoinbase) {
    this->timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch()).count();
    // La salida de la coinbase se añade aquí directamente
    this->outputs.push_back({amount, recipientAddress, ""}); // utxoId se establecerá después de calcular el id de la transacción
    this->inputs = {}; // Las transacciones coinbase no tienen entradas
    updateId(); // Calcula el ID de la transacción al construirla.
    // Actualizar utxoId para la salida coinbase después de que id esté disponible
    this->outputs[0].utxoId = this->id + ":" + std::to_string(0);
}

// Calcula el hash de la transacción (TxID).
std::string Transaction::calculateHash() const {
    std::stringstream ss;
    ss << timestamp << isCoinbase; 

    // Incluir todos los datos relevantes de las entradas (sin firmas ni claves públicas)
    for (const auto& input : inputs) {
        ss << input.prevTxId << input.outputIndex;
    }

    // Incluir todos los datos relevantes de las salidas
    for (const auto& output : outputs) {
        ss << output.amount << output.recipientAddress;
    }

    std::string data_to_hash = ss.str();
    Radix::RandomXHash hash_bytes = Radix::SHA256(data_to_hash); 
    return Radix::toHexString(hash_bytes);
}

// Firma la transacción.
// En un modelo UTXO, esto implica firmar el hash de la transacción y
// asignar la clave pública y la firma a cada input.
void Transaction::sign(const Radix::KeyPair& keyPair) {
    if (isCoinbase) {
        std::cerr << "Advertencia: Intentando firmar una transaccion coinbase. Las transacciones coinbase no requieren firma estandar." << std::endl;
        return;
    }

    // El hash que se firmará es el ID de la transacción.
    std::string transaction_hash_str = calculateHash();
    Radix::RandomXHash message_hash_bytes;
    Radix::fromHexString(transaction_hash_str, message_hash_bytes);

    // Asigna la clave pública y la firma a cada input de la transacción.
    // Esto asume que todos los inputs son gastados por la misma KeyPair.
    // En un sistema real, cada input podría ser de un propietario diferente
    // y requeriría su propia firma.
    for (auto& input : inputs) {
        // Opcional: Verificar que la clave pública del input coincida con la clave pública del KeyPair
        // si el input ya tiene una clave pública asignada.
        if (!input.pubKey.empty() && keyPair.getPublicKey() != input.pubKey) {
            std::cerr << "Advertencia: La clave publica en el input no coincide con la clave publica de la KeyPair proporcionada." << std::endl;
            // Podrías lanzar un error aquí si quieres una validación más estricta.
        }
        input.pubKey = keyPair.getPublicKey();
        input.signature = keyPair.sign(message_hash_bytes); // Cada input firma el mismo hash de transacción
    }
}

// Verifica la validez de la transacción, utilizando el conjunto de UTXO disponible.
bool Transaction::isValid(const std::map<std::string, TransactionOutput>& utxoSet) const {
    if (isCoinbase) {
        // Validaciones específicas para transacciones coinbase
        if (!inputs.empty()) {
            std::cerr << "Error de validacion de coinbase: Las transacciones coinbase no deben tener inputs." << std::endl;
            return false;
        }
        if (outputs.empty()) {
            std::cerr << "Error de validacion de coinbase: Las transacciones coinbase deben tener al menos una salida." << std::endl;
            return false;
        }
        // Puedes añadir más reglas de validación de coinbase aquí (ej. monto de recompensa).
        // No se verifica firma en coinbase.
        return true; 
    }

    // Para transacciones estándar:
    // 1. Verificar que existan inputs y outputs
    if (inputs.empty()) {
        std::cerr << "Error de validacion: Transaccion no coinbase sin inputs." << std::endl;
        return false;
    }
    if (outputs.empty()) {
        std::cerr << "Error de validacion: Transaccion sin outputs." << std::endl;
        return false;
    }

    double totalInputAmount = 0.0;
    // 2. Validar cada entrada (Input)
    for (const auto& input : inputs) {
        // a) Verificar que la UTXO referenciada exista en el `utxoSet`
        std::string utxoKey = input.prevTxId + ":" + std::to_string(input.outputIndex);
        auto it = utxoSet.find(utxoKey);
        if (it == utxoSet.end()) {
            std::cerr << "Error de validacion: Input hace referencia a UTXO inexistente o ya gastada: " << utxoKey << std::endl;
            return false;
        }
        const TransactionOutput& referencedOutput = it->second;

        // b) Verificar que la dirección de la UTXO referenciada coincide con la clave pública del input
        // (es decir, que el firmante es el propietario legítimo de la UTXO)
        std::string expectedAddress = Radix::KeyPair::deriveAddress(input.pubKey);
        if (referencedOutput.recipientAddress != expectedAddress) {
            std::cerr << "Error de validacion: La UTXO referenciada no pertenece al firmante del input. UTXO Address: " 
                      << referencedOutput.recipientAddress << ", Input PubKey Address: " << expectedAddress << std::endl;
            return false;
        }
        
        // c) Verificar la firma del input.
        // El hash a verificar es el TxID de *esta* transacción (la que contiene el input).
        std::string currentTxHashStr = calculateHash();
        Radix::RandomXHash messageHashBytes;
        Radix::fromHexString(currentTxHashStr, messageHashBytes);

        if (!Radix::KeyPair::verify(input.pubKey, messageHashBytes, input.signature)) {
            std::cerr << "Error de validacion: Firma invalida para input en transaccion " << id << std::endl;
            std::cerr << "  Input: prevTxId=" << input.prevTxId << ", outputIndex=" << input.outputIndex << std::endl;
            std::cerr << "  PublicKey: " << Radix::toHexString(input.pubKey) << std::endl;
            std::cerr << "  Signature: " << Radix::toHexString(input.signature) << std::endl;
            return false;
        }

        totalInputAmount += referencedOutput.amount;
    }

    double totalOutputAmount = 0.0;
    for (const auto& output : outputs) {
        totalOutputAmount += output.amount;
    }

    // 3. Verificar que la suma de las entradas cubra la suma de las salidas (y posible tarifa).
    // Por simplicidad, asumimos que no hay tarifas o que la tarifa es 0.
    if (totalInputAmount < totalOutputAmount) {
        std::cerr << "Error de validacion: Monto insuficiente de inputs. Inputs: " << totalInputAmount 
                  << ", Outputs: " << totalOutputAmount << std::endl;
        return false;
    }

    // 4. Verificar que el `id` de la transacción se haya calculado correctamente.
    // Esto se hace después de todas las otras validaciones, ya que el ID depende de los inputs/outputs.
    std::string calculatedId = calculateHash();
    if (id != calculatedId) {
        std::cerr << "Error de validacion: El ID de la transaccion no coincide. Calculado: " << calculatedId << ", Almacenado: " << id << std::endl;
        return false;
    }

    return true; // La transacción es válida
}

// Convierte la transacción a una representación de cadena para visualización
std::string Transaction::toString() const {
    std::stringstream ss;
    ss << "Transaction ID: " << id << "\n";
    ss << "  Is Coinbase: " << (isCoinbase ? "Yes" : "No") << "\n";
    ss << "  Timestamp: " << timestamp << "\n";

    ss << "  Inputs (" << inputs.size() << "):\n";
    if (inputs.empty() && !isCoinbase) {
        ss << "    [No inputs para transaccion estandar, error o simulado]\n";
    } else {
        for (const auto& input : inputs) {
            ss << input.toString();
        }
    }

    ss << "  Outputs (" << outputs.size() << "):\n";
    if (outputs.empty()) {
        ss << "    [No outputs]\n";
    } else {
        for (const auto& output : outputs) {
            ss << output.toString();
        }
    }
    return ss.str();
}

// Actualiza el ID de la transacción (basado en calculateHash)
void Transaction::updateId() {
    id = calculateHash();
}

} // namespace Radix
