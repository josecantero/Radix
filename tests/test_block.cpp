#include <gtest/gtest.h>
#include "block.h"
#include "randomx_util.h"
#include <openssl/provider.h>

class BlockTest : public ::testing::Test {
protected:
    Soverx::RandomXContext rxContext;
    
    void SetUp() override {
        OSSL_PROVIDER_load(NULL, "default");
        OSSL_PROVIDER_load(NULL, "base");
    }
};

// Test: Genesis block creation
TEST_F(BlockTest, GenesisBlockCreation) {
    std::vector<Soverx::Transaction> txs;
    Soverx::Block genesis(0, "0", txs, 1, rxContext);
    
    // Hash needs to be calculated explicitly
    genesis.hash = genesis.calculateHash();
    
    EXPECT_EQ(genesis.version, 0);
    EXPECT_EQ(genesis.prevHash, "0");
    EXPECT_GT(genesis.hash.length(), 0);
    EXPECT_EQ(genesis.difficulty, 1);
}

// Test: Block with transactions
TEST_F(BlockTest, BlockWithTransactions) {
    Soverx::Transaction coinbase("svx_miner", 5000000000ULL, true);
    std::vector<Soverx::Transaction> txs = {coinbase};
    
    Soverx::Block block(1, "prev_hash", txs, 1, rxContext);
    
    EXPECT_EQ(block.version, 1);
    EXPECT_EQ(block.transactions.size(), 1);
    EXPECT_EQ(block.transactions[0].id, coinbase.id);
}

// Test: Block hash calculation consistency
TEST_F(BlockTest, HashCalculationConsistency) {
    std::vector<Soverx::Transaction> txs;
    Soverx::Block block(1, "prev_hash", txs, 1, rxContext);
    
    // Hash should be deterministic
    std::string hash1 = block.calculateHash();
    std::string hash2 = block.calculateHash();
    
    EXPECT_EQ(hash1, hash2);
    
    // Assign hash to block
    block.hash = hash1;
    EXPECT_EQ(hash1, block.hash);
}

// Test: Different blocks have different hashes
TEST_F(BlockTest, DifferentBlocksDifferentHashes) {
    std::vector<Soverx::Transaction> txs1;
    std::vector<Soverx::Transaction> txs2;
    
    Soverx::Block block1(1, "prev_hash_1", txs1, 1, rxContext);
    Soverx::Block block2(2, "prev_hash_2", txs2, 1, rxContext);
    
    // Calculate hashes
    std::string hash1 = block1.calculateHash();
    std::string hash2 = block2.calculateHash();
    
    EXPECT_NE(hash1, hash2);
}

// Test: Block mining (difficulty 1) - SLOW TEST, marked as such
TEST_F(BlockTest, MiningDifficulty1) {
    std::vector<Soverx::Transaction> txs;
    Soverx::Block block(1, "prev_hash", txs, 1, rxContext);
    
    // Record initial state
    uint64_t initialNonce = block.nonce;
    std::string hashBeforeMining = block.hash;
    
    std::atomic<bool> running(true);
    block.mineBlock(1, running);
    
    // After mining:
    // 1. Nonce should have changed (or block should be mined with valid hash)
    // Note: Sometimes nonce might still be 0 if hash already met difficulty
    // So we check if hash meets difficulty requirement instead
    EXPECT_EQ(block.hash[0], '0');
    
    // Hash should have changed from initial
    EXPECT_NE(block.hash, hashBeforeMining);
}

// Test: Mining can be stopped
TEST_F(BlockTest, MiningCanBeInterrupted) {
    std::vector<Soverx::Transaction> txs;
    Soverx::Block block(100, "prev_hash", txs, 5, rxContext); // High difficulty
    
    std::atomic<bool> running(false); // Immediately stop
    block.mineBlock(5, running); // Use mineBlock with difficulty parameter
    
    // Mining should exit quickly without finding solution
    EXPECT_LT(block.nonce, 1000); // Shouldn't have done much work
}

// Test: Block validation with valid hash
TEST_F(BlockTest, BlockValidationValid) {
    std::vector<Soverx::Transaction> txs;
    Soverx::Block block(1, "prev_hash", txs, 1, rxContext);
    
    std::atomic<bool> running(true);
    block.mineBlock(1, running);
    
    std::map<std::string, Soverx::TransactionOutput> utxoSet;
    
    // Mined block should be valid
    EXPECT_TRUE(block.isValid(rxContext, utxoSet));
}

// Test: Block validation with tampered hash
TEST_F(BlockTest, BlockValidationInvalid) {
    std::vector<Soverx::Transaction> txs;
    Soverx::Block block(1, "prev_hash", txs, 1, rxContext);
    
    std::atomic<bool> running(true);
    block.mineBlock(1, running);
    
    // Tamper with hash
    block.hash = "invalid_hash_12345";
    
    std::map<std::string, Soverx::TransactionOutput> utxoSet;
    
    // Should be invalid
    EXPECT_FALSE(block.isValid(rxContext, utxoSet));
}

// Test: Block serialization and deserialization
TEST_F(BlockTest, Serialization) {
    Soverx::Transaction coinbase("svx_miner", 5000000000ULL, true);
    std::vector<Soverx::Transaction> txs = {coinbase};
    
    Soverx::Block original(5, "prev_hash_abc", txs, 1, rxContext);
    original.nonce = 12345;
    original.timestamp = 1638360000;
    original.hash = original.calculateHash();
    
    // Serialize
    std::stringstream ss;
    original.serialize(ss);
    
    // Deserialize into new block
    Soverx::Block deserialized(0, "", {}, 0, rxContext);
    deserialized.deserialize(ss);
    
    // Verify all fields match
    EXPECT_EQ(deserialized.version, original.version);
    EXPECT_EQ(deserialized.prevHash, original.prevHash);
    EXPECT_EQ(deserialized.nonce, original.nonce);
    EXPECT_EQ(deserialized.timestamp, original.timestamp);
    EXPECT_EQ(deserialized.hash, original.hash);
    EXPECT_EQ(deserialized.difficulty, original.difficulty);
    EXPECT_EQ(deserialized.transactions.size(), 1);
    EXPECT_EQ(deserialized.transactions[0].id, coinbase.id);
}

// Test: Block merkle root calculation
TEST_F(BlockTest, MerkleRootCalculation) {
    Soverx::Transaction tx1("svx_addr1", 1000000000ULL, true);
    Soverx::Transaction tx2("svx_addr2", 2000000000ULL, true);
    std::vector<Soverx::Transaction> txs = {tx1, tx2};
    
    Soverx::Block block(1, "prev", txs, 1, rxContext);
    
    // Merkle root should be calculated
    EXPECT_GT(block.merkleRoot.length(), 0);
    
    // Should be deterministic
    Soverx::Block block2(1, "prev", txs, 1, rxContext);
    EXPECT_EQ(block.merkleRoot, block2.merkleRoot);
}
