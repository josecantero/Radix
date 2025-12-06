#include <gtest/gtest.h>
#include "crypto.h"
#include <openssl/provider.h>

class CryptoTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize OpenSSL providers for tests
        OSSL_PROVIDER_load(NULL, "default");
        OSSL_PROVIDER_load(NULL, "base");
    }
};

// Test: KeyPair generation
TEST_F(CryptoTest, KeyPairGeneration) {
    Radix::KeyPair kp;
    
    // Public key should be 33 or 65 bytes (compressed or uncompressed)
    EXPECT_TRUE(kp.getPublicKey().size() == 33 || 
                kp.getPublicKey().size() == 65);
    
    // Private key should be 32 bytes
    EXPECT_EQ(kp.getPrivateKey().size(), 32);
    
    // Address should start with "R" (Base58 format)
    EXPECT_EQ(kp.getAddress().substr(0, 1), "R");
    // Address should be reasonably long (Base58 encoded)
    EXPECT_GT(kp.getAddress().length(), 20);
}

// Test: Deterministic key from private key
TEST_F(CryptoTest, DeterministicKeyGeneration) {
    Radix::PrivateKey privKey;
    privKey.fill(0x42); // Fill with test pattern
    
    Radix::KeyPair kp1(privKey);
    Radix::KeyPair kp2(privKey);
    
    // Same private key should produce same public key and address
    EXPECT_EQ(kp1.getPublicKey(), kp2.getPublicKey());
    EXPECT_EQ(kp1.getAddress(), kp2.getAddress());
}

// Test: Sign and verify
TEST_F(CryptoTest, SignAndVerify) {
    Radix::KeyPair kp;
    
    // Create a message hash
    std::string message = "Hello Radix!";
    Radix::RandomXHash msgHash = Radix::SHA256(message);
    
    // Sign the hash
    Radix::Signature sig = kp.sign(msgHash);
    
    // Signature should not be empty
    EXPECT_GT(sig.size(), 0);
    
    // Verify signature
    bool valid = Radix::KeyPair::verify(kp.getPublicKey(), msgHash, sig);
    EXPECT_TRUE(valid);
}

// Test: Invalid signature detection
TEST_F(CryptoTest, InvalidSignatureDetection) {
    Radix::KeyPair kp1, kp2;
    
    std::string message = "Test message";
    Radix::RandomXHash msgHash = Radix::SHA256(message);
    
    // Sign with kp1
    Radix::Signature sig = kp1.sign(msgHash);
    
    // Try to verify with kp2's public key (should fail)
    bool valid = Radix::KeyPair::verify(kp2.getPublicKey(), msgHash, sig);
    EXPECT_FALSE(valid);
}

// Test: Address derivation consistency
TEST_F(CryptoTest, AddressDerivation) {
    Radix::KeyPair kp;
    
    // Derive address from public key
    std::string derivedAddr = Radix::KeyPair::deriveAddress(kp.getPublicKey());
    
    // Should match KeyPair's address
    EXPECT_EQ(derivedAddr, kp.getAddress());
}

// Test: SHA256 consistency
TEST_F(CryptoTest, SHA256Consistency) {
    std::string message = "Radix Blockchain";
    
    // Same input should produce same hash
    Radix::RandomXHash hash1 = Radix::SHA256(message);
    Radix::RandomXHash hash2 = Radix::SHA256(message);
    
    EXPECT_EQ(hash1, hash2);
    
    // Different input should produce different hash
    Radix::RandomXHash hash3 = Radix::SHA256("Different message");
    EXPECT_NE(hash1, hash3);
}
