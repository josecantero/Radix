#include <gtest/gtest.h>
#include "blockchain.h"
#include <openssl/provider.h>

class BlockchainTest : public ::testing::Test {
protected:
    Radix::RandomXContext rxContext;
    
    void SetUp() override {
        OSSL_PROVIDER_load(NULL, "default");
        OSSL_PROVIDER_load(NULL, "base");
    }
};

// Test: Blockchain initialization with genesis block
TEST_F(BlockchainTest, Initialization) {
    Radix::Blockchain bc(1, rxContext);
    
    // Should have exactly one block (genesis)
    EXPECT_EQ(bc.getChainSize(), 1);
    
    // Genesis block should have version 1 (not 0)
    const Radix::Block& genesis = bc.getLatestBlock();
    EXPECT_EQ(genesis.version, 1); // Genesis is version 1
    // prevHash is 64-character hex string of zeros, not just "0"
    EXPECT_EQ(genesis.prevHash.length(), 64);
    EXPECT_EQ(genesis.prevHash, "0000000000000000000000000000000000000000000000000000000000000000");
}

// Test: Get block hash by index
TEST_F(BlockchainTest, GetBlockHash) {
    Radix::Blockchain bc(1, rxContext);
    
    // Genesis block at index 0
    std::string genesisHash = bc.getBlockHash(0);
    EXPECT_GT(genesisHash.length(), 0);
    EXPECT_EQ(genesisHash, bc.getLatestBlock().hash);
    
    // Invalid index should return empty string
   std::string invalidHash = bc.getBlockHash(999);
    EXPECT_EQ(invalidHash, "");
}

// Test: Get block height by hash
TEST_F(BlockchainTest, GetBlockHeight) {
    Radix::Blockchain bc(1, rxContext);
    
    std::string genesisHash = bc.getLatestBlock().hash;
    
    // Should find genesis at height 0
    int height = bc.getBlockHeight(genesisHash);
    EXPECT_EQ(height, 0);
    
    // Non-existent hash should return -1
    int invalidHeight = bc.getBlockHeight("non_existent_hash");
    EXPECT_EQ(invalidHeight, -1);
}

// Test: Balance calculation - initial state
TEST_F(BlockchainTest, InitialBalanceIsZero) {
    Radix::Blockchain bc(1, rxContext);
    
    std::string testAddress = "radix_test_address";
    uint64_t balance = bc.getBalanceOfAddress(testAddress);
    
    EXPECT_EQ(balance, 0);
}

// Test: Balance after mining
TEST_F(BlockchainTest, BalanceAfterMining) {
    Radix::Blockchain bc(1, rxContext);
    
    std::string minerAddr = "radix_miner";
    
    // Mine a block (this will take a few seconds due to PoW)
    std::atomic<bool> running(true);
    bc.minePendingTransactions(minerAddr, running);
    
    // Miner should now have the block reward
    uint64_t balance = bc.getBalanceOfAddress(minerAddr);
    EXPECT_GT(balance, 0);
    
    // Chain should have 2 blocks now (genesis + mined)
    EXPECT_EQ(bc.getChainSize(), 2);
}

// Test: Chain validation - valid chain
TEST_F(BlockchainTest, ChainValidationValid) {
    Radix::Blockchain bc(1, rxContext);
    
    // Genesis block should be valid
    EXPECT_TRUE(bc.isChainValid());
    
    // Mine another block
    std::atomic<bool> running(true);
    bc.minePendingTransactions("radix_miner", running);
    
    // Chain should still be valid
    EXPECT_TRUE(bc.isChainValid());
}

// Test: Add transaction to pending
TEST_F(BlockchainTest, AddTransactionBasic) {
    Radix::Blockchain bc(1, rxContext);
    
    // Mine initial block to create UTXO
    std::atomic<bool> running(true);
    bc.minePendingTransactions("radix_miner", running);
    
    // Note: Creating a valid transaction requires complex UTXO setup
    // For this basic test, we just verify the method exists and handles
    // invalid transactions correctly
    
    Radix::Transaction invalidTx("radix_recipient", 1000000000ULL, false);
    // This should fail because it's not a coinbase but has no inputs
    bool added = bc.addTransaction(invalidTx);
    
    // Should reject invalid transaction
    EXPECT_FALSE(added);
}

// Test: Get blocks from height
TEST_F(BlockchainTest, GetBlocksFromHeight) {
    Radix::Blockchain bc(1, rxContext);
    
    // Mine a few blocks
    std::atomic<bool> running(true);
    bc.minePendingTransactions("radix_miner1", running);
    bc.minePendingTransactions("radix_miner2", running);
    
    // Should have 3 blocks total (genesis + 2 mined)
    EXPECT_EQ(bc.getChainSize(), 3);
    
    // Get blocks starting from height 1
    auto blocks = bc.getBlocksFromHeight(1, 10);
    
    // Should get 2 blocks
    // Note: version auto-increments with each mined block
    EXPECT_EQ(blocks.size(), 2);
    EXPECT_GT(blocks[0].version, 0);
    EXPECT_GT(blocks[1].version, blocks[0].version);
}

// Test: Get blocks with max count limit
TEST_F(BlockchainTest, GetBlocksWithLimit) {
    Radix::Blockchain bc(1, rxContext);
    
    // Mine 2 blocks
    std::atomic<bool> running(true);
    bc.minePendingTransactions("radix_miner1", running);
    bc.minePendingTransactions("radix_miner2", running);
    
    // Request only 1 block starting from index 0
    auto blocks = bc.getBlocksFromHeight(0, 1);
    
    EXPECT_EQ(blocks.size(), 1);
    // First mined block has auto-incremented version
    EXPECT_GT(blocks[0].version, 0); // Version is auto-incremented
}

// Test: Get block at specific height
TEST_F(BlockchainTest, GetBlockAtHeight) {
    Radix::Blockchain bc(1, rxContext);
    
    // Genesis block at height 0
    const Radix::Block* genesis = bc.getBlockAtHeight(0);
    ASSERT_NE(genesis, nullptr);
    EXPECT_EQ(genesis->version, 1); // Genesis is version 1
    
    // Height beyond chain should return nullptr
    const Radix::Block* invalid = bc.getBlockAtHeight(999);
    EXPECT_EQ(invalid, nullptr);
}

// Test: UTXO set access
TEST_F(BlockchainTest, UTXOSetAccess) {
    Radix::Blockchain bc(1, rxContext);
    
    // Initially has genesis coinbase UTXO
    const auto& utxoSet = bc.getUtxoSet();
    // Genesis block creates a coinbase transaction, so UTXO set is not empty
    EXPECT_EQ(utxoSet.size(), 1);
    
    // After mining, should have UTXO for miner
    std::atomic<bool> running(true);
    bc.minePendingTransactions("radix_miner", running);
    
    const auto& utxoSetAfterMining = bc.getUtxoSet();
    EXPECT_GT(utxoSetAfterMining.size(), 0);
}

// Test: Blockchain persistence (save/load)
TEST_F(BlockchainTest, BlockchainPersistence) {
    std::string testFile = "test_blockchain_temp.dat";
    
    // Create blockchain and mine a block
    {
        Radix::Blockchain bc(1, rxContext);
        std::atomic<bool> running(true);
        bc.minePendingTransactions("radix_miner", running);
        
        // Save to file
        bc.saveChain(testFile);
    }
    
    // Load in new blockchain
    {
        Radix::Blockchain bc2(1, rxContext);
        bool loaded = bc2.loadChain(testFile);
        
        EXPECT_TRUE(loaded);
        EXPECT_EQ(bc2.getChainSize(), 2); // Genesis + mined block
    }
    
    // Cleanup
    std::remove(testFile.c_str());
}
