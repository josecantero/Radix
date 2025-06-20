#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <memory> // For std::unique_ptr

namespace Radix {

// Type for representing currency amount (e.g., satoshis or rads)
using Rads = uint64_t;
using Address = std::string;
using RandomXHash = std::array<uint8_t, 32>; // Definition forward or include if not coming from Block.h

// Forward declaration for RandomXContext (needed if its used in a function signature in the header)
class RandomXContext;

// Structure for representing a transaction input (UTXO being spent)
struct TxInput {
    RandomXHash prevTxId;    // ID of the previous transaction from which this output comes
    uint32_t outputIndex;    // Index of the output in the previous transaction
    std::vector<uint8_t> signature; // Digital signature proving ownership

    // Constructor
    TxInput(const RandomXHash& pTxId, uint32_t oIdx, const std::vector<uint8_t>& sig = {});

    // Serialization function for hashing
    std::vector<uint8_t> serializeForHash() const;
    std::string toString() const;
};

// Structure for representing a transaction output (new UTXOs created)
struct TxOutput {
    Rads value;         // Amount of Rads
    Address toAddress;  // Recipient's address

    // Constructor
    TxOutput(Rads val, const Address& toAddr);

    // Serialization function for hashing
    std::vector<uint8_t> serializeForHash() const;
    std::string toString() const;
};

class Transaction {
public:
    RandomXHash txId; // Hash of the transaction (unique identifier)
    uint32_t version;
    uint32_t timestamp;
    std::vector<TxInput> inputs;
    std::vector<TxOutput> outputs;
    std::string data; // Field for arbitrary data or a message (e.g., OP_RETURN)

    // Constructor for regular transactions
    Transaction(const std::vector<TxInput>& inputs, const std::vector<TxOutput>& outputs, const std::string& data = "");

    // Default constructor
    Transaction();

    // Calculates the hash of the transaction for its ID (includes all relevant parts)
    RandomXHash calculateHash(RandomXContext& rxContext) const;
    
    // Calculates the hash of the common transaction data for signing (excludes existing signatures)
    std::vector<uint8_t> serializeCommonDataForSigning() const;
    
    // Serializes all transaction data for its ID calculation
    std::vector<uint8_t> serializeAllData() const;

    // --- NEW DECLARATION HERE! ---
    RandomXHash calculateHashForSigning(RandomXContext& rxContext) const;
    // -----------------------------

    std::string toString() const;

private:
    // Helper to serialize input/output lists for hashing
    std::vector<uint8_t> serializeInputsForHash() const;
    std::vector<uint8_t> serializeOutputsForHash() const;
};

// Derived class for Coinbase transactions (block reward)
class CoinbaseTransaction : public Transaction {
public:
    // Coinbase transaction constructor
    // Coinbase transactions have no inputs, only outputs and additional data
    CoinbaseTransaction(Rads reward, const Address& minerAddress, const std::string& data = "");
};

} // namespace Radix

#endif // TRANSACTION_H