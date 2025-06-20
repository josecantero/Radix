#include "transaction.h"
#include "randomx_util.h" // Para toHexString y RandomXContext
#include <iostream>
#include <sstream>
#include <iomanip> // Para std::setw, std::setfill
#include <limits>  // ¡AÑADE ESTO para std::numeric_limits!
#include <chrono>  // ¡AÑADE ESTO para std::chrono!

namespace Radix {

// --- Implementación de TxInput ---

TxInput::TxInput(const RandomXHash& pTxId, uint32_t oIdx, const std::vector<uint8_t>& sig)
    : prevTxId(pTxId), outputIndex(oIdx), signature(sig) {}

std::vector<uint8_t> TxInput::serializeForHash() const {
    std::vector<uint8_t> data;
    // Serializar prevTxId (32 bytes)
    for (uint8_t byte : prevTxId) {
        data.push_back(byte);
    }
    // Serializar outputIndex (uint32_t)
    for (int i = 0; i < 4; ++i) {
        data.push_back((outputIndex >> (8 * i)) & 0xFF);
    }
    // NOTA: La firma NO se incluye al calcular el hash de la transacción para su ID.
    // Solo se incluiría al verificar la firma de un input específico.
    return data;
}

std::string TxInput::toString() const {
    std::stringstream ss;
    ss << "    Input:\n";
    ss << "      PrevTxId: " << toHexString(prevTxId) << "\n";
    ss << "      OutputIndex: " << outputIndex << "\n";
    // ss << "      Signature: " << toHexString(signature) << "\n"; // No mostrar por ahora si está vacía
    return ss.str();
}

// --- Implementación de TxOutput ---

TxOutput::TxOutput(Rads val, const Address& toAddr)
    : value(val), toAddress(toAddr) {}

std::vector<uint8_t> TxOutput::serializeForHash() const {
    std::vector<uint8_t> data;
    // Serializar value (uint64_t)
    for (int i = 0; i < 8; ++i) {
        data.push_back((value >> (8 * i)) & 0xFF);
    }
    // Serializar toAddress (string, longitud + bytes)
    // Usamos la longitud de la cadena como un uint32_t para la serialización.
    uint32_t addressLen = static_cast<uint32_t>(toAddress.length());
    for (int i = 0; i < 4; ++i) {
        data.push_back((addressLen >> (8 * i)) & 0xFF);
    }
    for (char c : toAddress) {
        data.push_back(static_cast<uint8_t>(c));
    }
    return data;
}

std::string TxOutput::toString() const {
    std::stringstream ss;
    ss << "    Output:\n";
    ss << "      Value: " << value << " Rads\n";
    ss << "      To Address: " << toAddress << "\n";
    return ss.str();
}

// --- Implementación de Transaction ---

// Constructor por defecto
Transaction::Transaction() 
    : version(1), data("") 
{
    txId.fill(0);
    // Inicializa el timestamp también en el constructor por defecto si lo usas
    timestamp = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}


// Constructor para transacciones regulares
Transaction::Transaction(const std::vector<TxInput>& inputs, const std::vector<TxOutput>& outputs, const std::string& data)
    : version(1), // Versión de la transacción, ej. 1
      timestamp(static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>( // ¡CORREGIDO! std::chrono
          std::chrono::system_clock::now().time_since_epoch()).count())),
      inputs(inputs),
      outputs(outputs),
      data(data)
{
    txId.fill(0); // Se calculará después
}

// Implementación del constructor de CoinbaseTransaction
CoinbaseTransaction::CoinbaseTransaction(Rads reward, const Address& minerAddress, const std::string& data)
    : Transaction() // Llama al constructor por defecto de Transaction
{
    this->version = 1; // Versión para Coinbase, puede ser diferente si se desea
    this->timestamp = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>( // ¡CORREGIDO! std::chrono
        std::chrono::system_clock::now().time_since_epoch()).count());
    this->data = data;

    // Las transacciones Coinbase tienen un input especial (generación de monedas)
    RandomXHash emptyHash;
    emptyHash.fill(0);
    // El índice de output puede ser std::numeric_limits<uint32_t>::max() o 0xFFFFFFFF para indicar coinbase
    inputs.emplace_back(emptyHash, std::numeric_limits<uint32_t>::max()); // ¡CORREGIDO! std::numeric_limits

    // La recompensa del bloque va a la dirección del minero
    outputs.emplace_back(reward, minerAddress);
}


// Serializa solo los datos relevantes para la firma (excluye la firma misma)
std::vector<uint8_t> Transaction::serializeCommonDataForSigning() const {
    std::vector<uint8_t> data_for_signing;

    // Version (uint32_t)
    for (int i = 0; i < 4; ++i) {
        data_for_signing.push_back((version >> (8 * i)) & 0xFF);
    }
    // Timestamp (uint32_t)
    for (int i = 0; i < 4; ++i) {
        data_for_signing.push_back((timestamp >> (8 * i)) & 0xFF);
    }

    // Inputs (sin las firmas)
    std::vector<uint8_t> inputs_data = serializeInputsForHash(); // Este método ya excluye las firmas
    data_for_signing.insert(data_for_signing.end(), inputs_data.begin(), inputs_data.end());

    // Outputs
    std::vector<uint8_t> outputs_data = serializeOutputsForHash();
    data_for_signing.insert(data_for_signing.end(), outputs_data.begin(), outputs_data.end());

    // Data (string)
    uint32_t dataLen = static_cast<uint32_t>(data.length());
    for (int i = 0; i < 4; ++i) {
        data_for_signing.push_back((dataLen >> (8 * i)) & 0xFF);
    }
    for (char c : data) {
        data_for_signing.push_back(static_cast<uint8_t>(c));
    }

    return data_for_signing;
}

// Serializa todos los datos de la transacción para su ID (hash completo)
std::vector<uint8_t> Transaction::serializeAllData() const {
    std::vector<uint8_t> all_data;

    // Version (uint32_t)
    for (int i = 0; i < 4; ++i) {
        all_data.push_back((version >> (8 * i)) & 0xFF);
    }
    // Timestamp (uint32_t)
    for (int i = 0; i < 4; ++i) {
        all_data.push_back((timestamp >> (8 * i)) & 0xFF);
    }

    // Inputs (incluyendo las firmas si las hubiera)
    // Para el ID de la transacción, las firmas NO DEBEN incluirse en el hash.
    // Usamos serializeInputsForHash que ya las excluye.
    std::vector<uint8_t> inputs_data = serializeInputsForHash();
    all_data.insert(all_data.end(), inputs_data.begin(), inputs_data.end());

    // Outputs
    std::vector<uint8_t> outputs_data = serializeOutputsForHash();
    all_data.insert(all_data.end(), outputs_data.begin(), outputs_data.end());

    // Data (string)
    uint32_t dataLen = static_cast<uint32_t>(data.length());
    for (int i = 0; i < 4; ++i) {
        all_data.push_back((dataLen >> (8 * i)) & 0xFF);
    }
    for (char c : data) {
        all_data.push_back(static_cast<uint8_t>(c));
    }

    return all_data;
}


// Calcula el hash de la transacción para su ID
RandomXHash Transaction::calculateHash(RandomXContext& rxContext) const {
    std::vector<uint8_t> serializedTx = serializeAllData(); // ¡CORREGIDO!
    return rxContext.calculateHash(serializedTx);
}

// Calcula el hash de la transacción para firmar
RandomXHash Transaction::calculateHashForSigning(RandomXContext& rxContext) const {
    std::vector<uint8_t> serializedTx = serializeCommonDataForSigning(); // ¡CORREGIDO!
    return rxContext.calculateHash(serializedTx);
}

// Helper para serializar inputs
std::vector<uint8_t> Transaction::serializeInputsForHash() const {
    std::vector<uint8_t> inputs_data;
    uint32_t numInputs = static_cast<uint32_t>(inputs.size());
    // Serializar el número de inputs
    for (int i = 0; i < 4; ++i) {
        inputs_data.push_back((numInputs >> (8 * i)) & 0xFF);
    }
    // Serializar cada input (sin la firma para el TxId)
    for (const auto& input : inputs) {
        std::vector<uint8_t> input_bytes = input.serializeForHash(); // Esto ya excluye la firma
        inputs_data.insert(inputs_data.end(), input_bytes.begin(), input_bytes.end());
    }
    return inputs_data;
}

// Helper para serializar outputs
std::vector<uint8_t> Transaction::serializeOutputsForHash() const {
    std::vector<uint8_t> outputs_data;
    uint32_t numOutputs = static_cast<uint32_t>(outputs.size());
    // Serializar el número de outputs
    for (int i = 0; i < 4; ++i) {
        outputs_data.push_back((numOutputs >> (8 * i)) & 0xFF);
    }
    // Serializar cada output
    for (const auto& output : outputs) {
        std::vector<uint8_t> output_bytes = output.serializeForHash();
        outputs_data.insert(outputs_data.end(), output_bytes.begin(), output_bytes.end());
    }
    return outputs_data;
}

std::string Transaction::toString() const {
    std::stringstream ss;
    ss << "Transaction:\n";
    ss << "  TxId: " << toHexString(txId) << "\n";
    ss << "  Version: " << version << "\n";
    ss << "  Timestamp: " << timestamp << "\n";
    ss << "  Data: '" << data << "'\n";
    ss << "  Inputs (" << inputs.size() << "):\n";
    for (const auto& input : inputs) {
        ss << input.toString();
    }
    ss << "  Outputs (" << outputs.size() << "):\n";
    for (const auto& output : outputs) {
        ss << output.toString();
    }
    return ss.str();
}

} // namespace Radix