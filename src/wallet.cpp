#include "wallet.h"
#include <fstream>
#include <stdexcept>
#include <iostream>

namespace Soverx {

Wallet::Wallet() {
    // KeyPair constructor generates random keys
}

Wallet::Wallet(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open wallet file: " + filename);
    }

    // Read private key (32 bytes)
    PrivateKey privKey;
    if (!file.read(reinterpret_cast<char*>(privKey.data()), privKey.size())) {
        throw std::runtime_error("Invalid wallet file format");
    }

    keyPair = KeyPair(privKey);
}

void Wallet::saveToFile(const std::string& filename) const {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open wallet file for writing: " + filename);
    }

    const PrivateKey& privKey = keyPair.getPrivateKey();
    file.write(reinterpret_cast<const char*>(privKey.data()), privKey.size());
}

std::string Wallet::getAddress() const {
    return keyPair.getAddress();
}

PublicKey Wallet::getPublicKey() const {
    return keyPair.getPublicKey();
}

Transaction Wallet::createTransaction(const std::string& recipient, uint64_t amount, 
                                      const std::map<std::string, TransactionOutput>& utxoSet) const {
    
    std::vector<TransactionInput> inputs;
    std::vector<TransactionOutput> outputs;
    
    uint64_t totalInputAmount = 0;
    std::string myAddress = getAddress();

    // 1. Select UTXOs
    for (const auto& [utxoKey, output] : utxoSet) {
        if (output.recipientAddress == myAddress) {
            totalInputAmount += output.amount;
            
            // Parse utxoKey (txId:index)
            size_t colonPos = utxoKey.find(':');
            std::string txId = utxoKey.substr(0, colonPos);
            uint64_t index = std::stoull(utxoKey.substr(colonPos + 1));

            // Create input (signature will be added later)
            inputs.emplace_back(txId, index, keyPair.getPublicKey(), Signature());

            if (totalInputAmount >= amount) {
                break;
            }
        }
    }

    if (totalInputAmount < amount) {
        throw std::runtime_error("Insufficient funds. Available: " + std::to_string(totalInputAmount) + ", Required: " + std::to_string(amount));
    }

    // 2. Create Outputs
    outputs.emplace_back(amount, recipient);

    // Change output
    if (totalInputAmount > amount) {
        outputs.emplace_back(totalInputAmount - amount, myAddress);
    }

    // 3. Create Transaction
    Transaction tx(inputs, outputs);

    // 4. Sign Transaction
    tx.sign(keyPair.getPrivateKey(), keyPair.getPublicKey(), utxoSet);

    return tx;
}

} // namespace Soverx
