#ifndef SOVERX_WALLET_H
#define SOVERX_WALLET_H

#include "crypto.h"
#include "transaction.h"
#include <string>
#include <vector>
#include <map>

namespace Soverx {

class Wallet {
public:
    // Constructor: Generates a new random wallet
    Wallet();
    // Constructor: Loads wallet from file
    Wallet(const std::string& filename);

    // Save wallet to file (private key)
    void saveToFile(const std::string& filename) const;
    
    // Getters
    std::string getAddress() const;
    PublicKey getPublicKey() const;

    // Create a transaction
    // utxoSet: The current UTXO set from the blockchain
    Transaction createTransaction(const std::string& recipient, uint64_t amount, 
                                  const std::map<std::string, TransactionOutput>& utxoSet) const;

private:
    KeyPair keyPair;
};

} // namespace Soverx

#endif // SOVERX_WALLET_H
