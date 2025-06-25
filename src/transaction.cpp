#include "transaction.h"
#include "crypto.h"       // Necesario para KeyPair::verify
#include "randomx_util.h" // Para toHexString
#include <iostream>
#include <sstream>
#include <algorithm>      // Para std::all_of
#include <openssl/sha.h>  // Añadido para SHA256

namespace Radix {

// --------------------------------------------------------------------------------
// TransactionInput (TxInput) Methods
// --------------------------------------------------------------------------------

std::string TxInput::toString() const {
    std::stringstream ss;
    ss << "  PrevTxId: " << toHexString(prevTxId) << "\n";
    ss << "  OutputIndex: " << outputIndex << "\n";
    ss << "  Signature: " << toHexString(signature) << "\n";
    ss << "  PubKey: " << toHexString(pubKey) << "\n"; 
    return ss.str();
}

// --------------------------------------------------------------------------------
// TransactionOutput (TxOutput) Methods
// --------------------------------------------------------------------------------

std::string TxOutput::toString() const {
    std::stringstream ss;
    ss << "  Amount: " << amount << "\n"; 
    ss << "  RecipientAddress: " << recipientAddress << "\n"; 
    return ss.str();
}

// --------------------------------------------------------------------------------
// Transaction Methods
// --------------------------------------------------------------------------------

// Constructor general para transacciones normales
Transaction::Transaction(const std::vector<TxInput>& inputs, const std::vector<TxOutput>& outputs, Radix::RandomXContext& rxContext)
    : inputs(inputs), outputs(outputs), isCoinbase(false) { 
    calculateTxId(rxContext);
}

// Constructor para transacciones Coinbase
Transaction::Transaction(const std::vector<TxOutput>& outputs, Radix::RandomXContext& rxContext)
    : outputs(outputs), isCoinbase(true) {
    this->inputs.clear(); 
    calculateTxId(rxContext);
}


void Transaction::calculateTxId(Radix::RandomXContext& rxContext) {
    std::stringstream ss;

    // Serializar inputs (excluyendo la firma y la clave pública para el TxId)
    // El TxId es un identificador de la transacción, no debe cambiar por la firma.
    for (const auto& input : inputs) {
        ss << toHexString(input.prevTxId) << input.outputIndex;
    }

    // Serializar outputs
    for (const auto& output : outputs) {
        ss << output.amount << output.recipientAddress; 
    }

    std::string txData = ss.str();
    
    // Usar SHA256 para el TxId (como en Bitcoin)
    unsigned char hash_digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)txData.data(), txData.size(), hash_digest);
    std::copy(hash_digest, hash_digest + SHA256_DIGEST_LENGTH, txId.begin());
}

// Serializa la transacción para imprimirla
std::string Transaction::toString() const {
    std::stringstream ss;
    ss << "Transaction ID: " << toHexString(txId) << "\n";
    ss << "  Is Coinbase: " << (isCoinbase ? "Yes" : "No") << "\n"; 
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

// Verifica las firmas de los inputs de la transacción
bool Transaction::verifySignatures(Radix::RandomXContext& rxContext) const {
    // 1. Las transacciones Coinbase no tienen entradas y, por lo tanto, no tienen firmas que verificar.
    if (this->isCoinbase) { // Usar el flag isCoinbase
        return true; 
    }

    // Hash de la transacción para la verificación de firmas (misma lógica que calculateTxId)
    // El mensaje que se firma es el hash de los inputs y outputs (sin las firmas)
    std::stringstream ss_for_hash;
    for (const auto& input : inputs) {
        ss_for_hash << toHexString(input.prevTxId) << input.outputIndex;
    }
    for (const auto& output : outputs) {
        ss_for_hash << output.amount << output.recipientAddress; 
    }
    std::string txDataToSign = ss_for_hash.str();

    Radix::RandomXHash txHashToVerify; 
    unsigned char hash_digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)txDataToSign.data(), txDataToSign.size(), hash_digest);
    std::copy(hash_digest, hash_digest + SHA256_DIGEST_LENGTH, txHashToVerify.begin());


    for (const auto& input : inputs) {
        if (input.signature.empty() || input.pubKey.empty()) { 
            std::cerr << "Error: Input con firma o clave publica vacia para verificar." << std::endl;
            return false;
        }
        // Verificar la firma usando KeyPair::verify
        if (!Radix::KeyPair::verify(input.pubKey, txHashToVerify, input.signature)) { 
            std::cerr << "Error: Firma invalida para input. TxId: " << Radix::toHexString(this->txId) << std::endl;
            std::cerr << "  Input: prevTxId=" << Radix::toHexString(input.prevTxId) 
                      << ", outputIndex=" << input.outputIndex << std::endl;
            std::cerr << "  PublicKey: " << Radix::toHexString(input.pubKey) << std::endl; 
            std::cerr << "  Signature: " << Radix::toHexString(input.signature) << std::endl;
            return false;
        }
    }
    return true;
}

} // namespace Radix