#include <gtest/gtest.h>
#include "transaction.h"
#include "crypto.h"
#include <sstream>
#include <openssl/provider.h>

class TransactionTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize OpenSSL
        OSSL_PROVIDER_load(NULL, "default");
        OSSL_PROVIDER_load(NULL, "base");
    }
};

// Test: Coinbase transaction creation
TEST_F(TransactionTest, CoinbaseCreation) {
    std::string recipientAddr = "svx_test_address";
    uint64_t amount = 5000000000ULL; // 50 RDX
    
    Soverx::Transaction coinbase(recipientAddr, amount, true);
    
    EXPECT_TRUE(coinbase.isCoinbase);
    EXPECT_EQ(coinbase.inputs.size(), 0);
    EXPECT_EQ(coinbase.outputs.size(), 1);
    EXPECT_EQ(coinbase.outputs[0].amount, amount);
    EXPECT_EQ(coinbase.outputs[0].recipientAddress, recipientAddr);
    EXPECT_GT(coinbase.id.length(), 0);
    EXPECT_GT(coinbase.timestamp, 0);
}

// Test: Normal transaction creation
TEST_F(TransactionTest, NormalTransactionCreation) {
    Soverx::TransactionInput input("prev_tx_id", 0, {}, {});
    Soverx::TransactionOutput output(1000000000ULL, "svx_recipient");
    
    std::vector<Soverx::TransactionInput> inputs = {input};
    std::vector<Soverx::TransactionOutput> outputs = {output};
    
    Soverx::Transaction tx(inputs, outputs);
    
    EXPECT_FALSE(tx.isCoinbase);
    EXPECT_EQ(tx.inputs.size(), 1);
    EXPECT_EQ(tx.outputs.size(), 1);
    EXPECT_GT(tx.id.length(), 0);
}

// Test: Transaction serialization/deserialization
TEST_F(TransactionTest, Serialization) {
    Soverx::Transaction original("svx_test", 1000000000ULL, true);
    
    // Serialize
    std::stringstream ss;
    original.serialize(ss);
    
    // Deserialize
    Soverx::Transaction deserialized;
    deserialized.deserialize(ss);
    
    // Verify
    EXPECT_EQ(deserialized.id, original.id);
    EXPECT_EQ(deserialized.timestamp, original.timestamp);
    EXPECT_EQ(deserialized.isCoinbase, original.isCoinbase);
    EXPECT_EQ(deserialized.outputs.size(), original.outputs.size());
    if (!deserialized.outputs.empty()) {
        EXPECT_EQ(deserialized.outputs[0].amount, original.outputs[0].amount);
        EXPECT_EQ(deserialized.outputs[0].recipientAddress, 
                 original.outputs[0].recipientAddress);
    }
}

// Test: Transaction hash calculation
TEST_F(TransactionTest, HashCalculation) {
    Soverx::Transaction tx1("svx_addr1", 1000000000ULL, true);
    Soverx::Transaction tx2("svx_addr2", 1000000000ULL, true);
    
    // Different transactions should have different hashes
    EXPECT_NE(tx1.id, tx2.id);
    
    // Same transaction data should produce same hash
    std::string hash1 = tx1.calculateHash();
    std::string hash2 = tx1.calculateHash();
    EXPECT_EQ(hash1, hash2);
}

// Test: Transaction validation - coinbase should always be valid
TEST_F(TransactionTest, CoinbaseValidation) {
    Soverx::Transaction coinbase("svx_miner", 5000000000ULL, true);
    std::map<std::string, Soverx::TransactionOutput> emptyUTXO;
    
    // Coinbase transactions don't need UTXO validation
    bool valid = coinbase.isValid(emptyUTXO);
    EXPECT_TRUE(valid);
}

// Test: Empty transaction inputs/outputs
TEST_F(TransactionTest, EmptyInputsOutputs) {
    std::vector<Soverx::TransactionInput> inputs;
    std::vector<Soverx::TransactionOutput> outputs;
    
    // Creating transaction with empty vectors should not crash
    Soverx::Transaction tx(inputs, outputs);
    
    EXPECT_EQ(tx.inputs.size(), 0);
    EXPECT_EQ(tx.outputs.size(), 0);
    EXPECT_FALSE(tx.isCoinbase);
}

// Test: Transaction output construction
TEST_F(TransactionTest, TransactionOutputConstruction) {
    uint64_t amount = 1234567890ULL;
    std::string address = "svx_recipient";
    
    Soverx::TransactionOutput output(amount, address);
    
    EXPECT_EQ(output.amount, amount);
    EXPECT_EQ(output.recipientAddress, address);
}

// Test: Transaction input construction
TEST_F(TransactionTest, TransactionInputConstruction) {
    std::string prevTxId = "previous_transaction_id";
    uint64_t outputIndex = 3;
    Soverx::PublicKey pubKey = {0x01, 0x02, 0x03};
    Soverx::Signature sig = {0x04, 0x05, 0x06};
    
    Soverx::TransactionInput input(prevTxId, outputIndex, pubKey, sig);
    
    EXPECT_EQ(input.prevTxId, prevTxId);
    EXPECT_EQ(input.outputIndex, outputIndex);
    EXPECT_EQ(input.pubKey, pubKey);
    EXPECT_EQ(input.signature, sig);
}
