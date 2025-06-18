#include "transaction.h"
#include <sstream>
#include <iomanip>
#include <chrono>

namespace Radix {

Transaction::Transaction() : timestamp(0) {
    txId.fill(0);
    timestamp = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

Transaction::Transaction(const std::string& _data) : data(_data) {
    txId.fill(0);
    timestamp = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::vector<uint8_t> Transaction::serialize() const {
    std::vector<uint8_t> bytes;

    // Serializar timestamp (4 bytes)
    bytes.push_back(static_cast<uint8_t>(timestamp & 0xFF));
    bytes.push_back(static_cast<uint8_t>((timestamp >> 8) & 0xFF));
    bytes.push_back(static_cast<uint8_t>((timestamp >> 16) & 0xFF));
    bytes.push_back(static_cast<uint8_t>((timestamp >> 24) & 0xFF));

    // Serializar el tamaño de los datos (como un uint32_t, para simplificar)
    uint32_t dataSize = data.length();
    bytes.push_back(static_cast<uint8_t>(dataSize & 0xFF));
    bytes.push_back(static_cast<uint8_t>((dataSize >> 8) & 0xFF));
    bytes.push_back(static_cast<uint8_t>((dataSize >> 16) & 0xFF));
    bytes.push_back(static_cast<uint8_t>((dataSize >> 24) & 0xFF));

    // Serializar los datos en sí
    bytes.insert(bytes.end(), data.begin(), data.end());

    return bytes;
}

TxId Transaction::calculateHash(RandomXContext& rxContext) const {
    std::vector<uint8_t> serializedData = serialize();
    // NOTA: Para IDs de transacción y Merkle trees, SHA256 es el algoritmo estándar,
    // NO RandomX. RandomX es solo para Proof of Work (minería).
    // Por simplicidad y para no introducir una nueva librería de hashing ahora,
    // usaremos RandomXContext para simular un hash para el TxID.
    // ¡Esto DEBE cambiarse a SHA256 o SHA3 en una implementación real!
    std::vector<uint8_t> seed_for_tx_hash(RANDOMX_HASH_SIZE, 0); // Semilla fija o basada en algo irrelevante
    return rxContext.calculateHash(serializedData, seed_for_tx_hash);
}

std::string Transaction::toString() const {
    std::stringstream ss;
    ss << "  TxId: " << toHexString(txId) << "\n"
       << "  Timestamp: " << timestamp << "\n"
       << "  Data: \"" << data << "\"";
    return ss.str();
}

// Implementación de CoinbaseTransaction
CoinbaseTransaction::CoinbaseTransaction(uint64_t val, const std::string& coinbase_data)
    : value(val), coinbaseData(coinbase_data) {
    // El timestamp se inicializa en el constructor base de Transaction
}

std::vector<uint8_t> CoinbaseTransaction::serialize() const {
    std::vector<uint8_t> bytes = Transaction::serialize(); // Serializa la parte de Transaction
    // Serializar valor (8 bytes)
    bytes.push_back(static_cast<uint8_t>(value & 0xFF));
    bytes.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    bytes.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    bytes.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    bytes.push_back(static_cast<uint8_t>((value >> 32) & 0xFF));
    bytes.push_back(static_cast<uint8_t>((value >> 40) & 0xFF));
    bytes.push_back(static_cast<uint8_t>((value >> 48) & 0xFF));
    bytes.push_back(static_cast<uint8_t>((value >> 56) & 0xFF));

    // Serializar tamaño de coinbaseData
    uint32_t coinbaseDataSize = coinbaseData.length();
    bytes.push_back(static_cast<uint8_t>(coinbaseDataSize & 0xFF));
    bytes.push_back(static_cast<uint8_t>((coinbaseDataSize >> 8) & 0xFF));
    bytes.push_back(static_cast<uint8_t>((coinbaseDataSize >> 16) & 0xFF));
    bytes.push_back(static_cast<uint8_t>((coinbaseDataSize >> 24) & 0xFF));

    // Serializar coinbaseData
    bytes.insert(bytes.end(), coinbaseData.begin(), coinbaseData.end());

    return bytes;
}

TxId CoinbaseTransaction::calculateHash(RandomXContext& rxContext) const {
    std::vector<uint8_t> serializedData = serialize();
    std::vector<uint8_t> seed_for_tx_hash(RANDOMX_HASH_SIZE, 0); // Semilla fija
    return rxContext.calculateHash(serializedData, seed_for_tx_hash);
}

std::string CoinbaseTransaction::toString() const {
    std::stringstream ss;
    ss << Transaction::toString() // Llama al toString de la clase base
       << "\n  Type: Coinbase Transaction\n"
       << "  Value: " << value << "\n"
       << "  Coinbase Data: \"" << coinbaseData << "\"";
    return ss.str();
}

} // namespace Radix