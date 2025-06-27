// transaction.cpp
#include "transaction.h"
#include "crypto.h" // Para Radix::SHA256, KeyPair
#include "randomx_util.h" // Para Radix::toHexString, Radix::RandomXHash, Radix::fromHexString

#include <sstream> // Para stringstream
#include <chrono> // Para timestamp
#include <algorithm> // Para std::all_of
#include <iostream> // Para std::cerr

namespace Radix {

// Constructor por defecto para transacciones (usado para coinbase por defecto)
Transaction::Transaction(bool isCoinbase)
    : isCoinbase(isCoinbase), timestamp(std::chrono::duration_cast<std::chrono::seconds>(
                                   std::chrono::system_clock::now().time_since_epoch()).count()) {
    updateId(); // Calcula y asigna el ID de la transacción
}

// Constructor completo
Transaction::Transaction(std::string id, bool isCoinbase, std::vector<TransactionInput> inputs,
                         std::vector<TransactionOutput> outputs, long long timestamp)
    : id(id), isCoinbase(isCoinbase), inputs(inputs), outputs(outputs), timestamp(timestamp) {}

// Calcula el hash único de la transacción (TxID).
// Este hash incluye todos los datos esenciales de la transacción, pero NO las firmas ni claves públicas
// de las entradas, ya que estas son pruebas, no parte del contenido base de la transacción.
std::string Transaction::calculateHash() const {
    std::stringstream ss;
    ss << (isCoinbase ? "coinbase" : "transaction"); // Identificador del tipo de transacción
    for (const auto& input : inputs) {
        // Incluye solo la parte de la entrada que se compromete al hash (prevTxId, outputIndex)
        ss << input.prevTxId << input.outputIndex;
    }
    for (const auto& output : outputs) {
        // Incluye la cantidad y la dirección del destinatario de cada salida
        ss << output.amount << output.recipientAddress;
    }
    ss << timestamp; // Incluye la marca de tiempo para asegurar unicidad

    std::string data = ss.str();
    // CORRECCIÓN: Llamar a Radix::SHA256 con un solo argumento std::string
    Radix::RandomXHash hash_bytes = Radix::SHA256(data); // Calcula SHA256 del string de datos
    return Radix::toHexString(hash_bytes); // Devuelve el hash en formato hexadecimal
}

// Calcula el hash que debe ser firmado por los remitentes de la transacción.
// En este diseño, es simplemente el ID de la transacción.
Radix::RandomXHash Transaction::getHashForSignature() const {
    std::string txIdStr = calculateHash(); // Obtiene el TxID como cadena hexadecimal
    Radix::RandomXHash hashBytes;
    // fromHexString está en randomx_util.h/cpp, por eso es importante que esté incluido
    Radix::fromHexString(txIdStr, hashBytes); // Convierte la cadena hexadecimal a un array de bytes
    return hashBytes;
}

// Firma todas las entradas de la transacción utilizando el par de claves del remitente.
void Transaction::sign(const Radix::KeyPair& signerKeys) {
    if (isCoinbase) {
        // Las transacciones de Coinbase no tienen entradas para firmar; son implícitamente "firmadas" por el minero.
        return;
    }

    Radix::RandomXHash hashToSign = getHashForSignature(); // El hash de la transacción a firmar

    // Itera sobre todas las entradas de la transacción.
    // En un modelo de blockchain simplificado como este, asumimos que todas las entradas son firmadas
    // por la misma clave del remitente. En una blockchain real, cada entrada de UTXO
    // sería firmada por el propietario de esa UTXO específica.
    for (auto& input : inputs) {
        input.signature = signerKeys.sign(hashToSign); // Firma el hash y obtiene la firma
        input.pubKey = signerKeys.getPublicKey(); // Almacena la clave pública del firmante
    }
    // No es necesario actualizar el ID aquí si calculateHash() no incluye firma/pubkey.
    // Si el ID se actualizara con firma/pubkey, esto causaría un cambio en el ID después de la firma,
    // lo cual no es el comportamiento estándar en Bitcoin (TxID es estable una vez creado el contenido).
}

// Verifica todas las firmas en las entradas de la transacción.
bool Transaction::isValid() const {
    // 1. Verifica que el ID de la transacción sea correcto.
    if (id.empty()) {
        std::cerr << "Error: El ID de la transaccion esta vacio." << std::endl;
        return false;
    }
    if (calculateHash() != id) {
        std::cerr << "Error: El ID de la transaccion no coincide. Recalculado: " << calculateHash() << ", Almacenado: " << id << std::endl;
        return false;
    }

    if (isCoinbase) {
        // Las transacciones de Coinbase no tienen entradas que verificar (solo outputs).
        return true;
    }

    // 2. Para transacciones que no son Coinbase, verifica que tengan entradas.
    if (inputs.empty()) {
        std::cerr << "Error: Transaccion no-coinbase no tiene entradas." << std::endl;
        return false;
    }

    // 3. Verifica la validez de cada entrada (especialmente la firma).
    Radix::RandomXHash hashToVerify = getHashForSignature(); // El hash a verificar contra la firma

    for (const auto& input : inputs) {
        if (input.signature.empty() || input.pubKey.empty()) {
            std::cerr << "Error: La entrada de transaccion carece de firma o clave publica." << std::endl;
            return false;
        }

        // Usa la función estática verify de KeyPair para verificar la firma.
        if (!Radix::KeyPair::verify(input.pubKey, hashToVerify, input.signature)) {
            std::cerr << "Error: Firma invalida para input. TxId: " << id << std::endl;
            std::cerr << "  Input: prevTxId=" << input.prevTxId << ", outputIndex=" << input.outputIndex << std::endl;
            // toHexString está disponible (de randomx_util.h)
            std::cerr << "  PublicKey: " << Radix::toHexString(input.pubKey) << std::endl;
            std::cerr << "  Signature: " << Radix::toHexString(input.signature) << std::endl;
            return false;
        }
    }
    return true; // La transacción es válida
}

// Convierte el objeto de transacción a una cadena legible para visualización.
std::string Transaction::toString() const {
    std::stringstream ss;
    ss << "Transaction ID: " << id << "\n";
    ss << "  Is Coinbase: " << (isCoinbase ? "Yes" : "No") << "\n";
    ss << "  Timestamp: " << timestamp << "\n";

    if (!inputs.empty()) {
        ss << "  Inputs (" << inputs.size() << "):\n";
        for (const auto& input : inputs) {
            ss << "    PrevTxId: " << input.prevTxId << "\n";
            ss << "    OutputIndex: " << input.outputIndex << "\n";
            ss << "    Signature: " << Radix::toHexString(input.signature) << "\n";
            ss << "    PubKey: " << Radix::toHexString(input.pubKey) << "\n";
        }
    } else {
        ss << "  Inputs (0):\n";
    }

    if (!outputs.empty()) {
        ss << "  Outputs (" << outputs.size() << "):\n";
        for (const auto& output : outputs) {
            ss << "    Amount: " << output.amount << "\n";
            ss << "    RecipientAddress: " << output.recipientAddress << "\n";
        }
    } else {
        ss << "  Outputs (0):\n";
    }
    return ss.str();
}

// Actualiza el ID de la transacción. Debe llamarse después de que todos los datos
// esenciales de la transacción (entradas y salidas) estén finalizados y antes de la firma,
// si el ID se basa solo en el contenido.
void Transaction::updateId() {
    id = calculateHash();
}

} // namespace Radix
