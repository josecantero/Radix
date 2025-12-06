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
    std::string recipientAddr = "radix_test_address";
    uint64_t amount = 5000000000ULL; // 50 RDX
    
    Radix::Transaction coinbase(recipientAddr, amount, true);
    
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
    Radix::TransactionInput input("prev_tx_id", 0, {}, {});
    Radix::TransactionOutput output(1000000000ULL, "radix_recipient");
    
    std::vector<Radix::TransactionInput> inputs = {input};
    std::vector<Radix::TransactionOutput> outputs = {output};
    
    Radix::Transaction tx(inputs, outputs);
    
    EXPECT_FALSE(tx.isCoinbase);
    EXPECT_EQ(tx.inputs.size(), 1);
    EXPECT_EQ(tx.outputs.size(), 1);
    EXPECT_GT(tx.id.length(), 0);
}

// Test: Transaction serialization/deserialization
TEST_F(TransactionTest, Serialization) {
    Radix::Transaction original("radix_test", 1000000000ULL, true);
    
    // Serialize
    std::stringstream ss;
    original.serialize(ss);
    
    // Deserialize
    Radix::Transaction deserialized;
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
    Radix::Transaction tx1("radix_addr1", 1000000000ULL, true);
    Radix::Transaction tx2("radix_addr2", 1000000000ULL, true);
    
    // Different transactions should have different hashes
    EXPECT_NE(tx1.id, tx2.id);
    
    // Same transaction data should produce same hash
    std::string hash1 = tx1.calculateHash();
    std::string hash2 = tx1.calculateHash();
    EXPECT_EQ(hash1, hash2);
}

// Test: Transaction validation - coinbase should always be valid
TEST_F(TransactionTest, CoinbaseValidation) {
    Radix::Transaction coinbase("radix_miner", 5000000000ULL, true);
    std::map<std::string, Radix::TransactionOutput> emptyUTXO;
    
    // Coinbase transactions don't need UTXO validation
    bool valid = coinbase.isValid(emptyUTXO);
    EXPECT_TRUE(valid);
}

// Test: Empty transaction inputs/outputs
TEST_F(TransactionTest, EmptyInputsOutputs) {
    std::vector<Radix::TransactionInput> inputs;
    std::vector<Radix::TransactionOutput> outputs;
    
    // Creating transaction with empty vectors should not crash
    Radix::Transaction tx(inputs, outputs);
    
    EXPECT_EQ(tx.inputs.size(), 0);
    EXPECT_EQ(tx.outputs.size(), 0);
    EXPECT_FALSE(tx.isCoinbase);
}

// Test: Transaction output construction
TEST_F(TransactionTest, TransactionOutputConstruction) {
    uint64_t amount = 1234567890ULL;
    std::string address = "radix_recipient";
    
    Radix::TransactionOutput output(amount, address);
    
    EXPECT_EQ(output.amount, amount);
    EXPECT_EQ(output.recipientAddress, address);
}

// Test: Transaction input construction
TEST_F(TransactionTest, TransactionInputConstruction) {
    std::string prevTxId = "previous_transaction_id";
    uint64_t outputIndex = 3;
    Radix::PublicKey pubKey = {0x01, 0x02, 0x03};
    Radix::Signature sig = {0x04, 0x05, 0x06};
    
    Radix::TransactionInput input(prevTxId, outputIndex, pubKey, sig);
    
    EXPECT_EQ(input.prevTxId, prevTxId);
    EXPECT_EQ(input.outputIndex, outputIndex);
    EXPECT_EQ(input.pubKey, pubKey);
    EXPECT_EQ(input.signature, sig);
}
