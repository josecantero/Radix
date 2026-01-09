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
    Soverx::KeyPair kp;
    
    // Public key should be 33 or 65 bytes (compressed or uncompressed)
    EXPECT_TRUE(kp.getPublicKey().size() == 33 || 
                kp.getPublicKey().size() == 65);
    
    // Private key should be 32 bytes
    EXPECT_EQ(kp.getPrivateKey().size(), 32);
    
    // Address should start with "svx_"
    EXPECT_EQ(kp.getAddress().substr(0, 4), "svx_");
    // Address should be reasonably long (Base58 encoded)
    EXPECT_GT(kp.getAddress().length(), 20);
}

// Test: Deterministic key from private key
TEST_F(CryptoTest, DeterministicKeyGeneration) {
    Soverx::PrivateKey privKey;
    privKey.fill(0x42); // Fill with test pattern
    
    Soverx::KeyPair kp1(privKey);
    Soverx::KeyPair kp2(privKey);
    
    // Same private key should produce same public key and address
    EXPECT_EQ(kp1.getPublicKey(), kp2.getPublicKey());
    EXPECT_EQ(kp1.getAddress(), kp2.getAddress());
}

// Test: Sign and verify
TEST_F(CryptoTest, SignAndVerify) {
    Soverx::KeyPair kp;
    
    // Create a message hash
    std::string message = "Hello Soverx!";
    Soverx::RandomXHash msgHash = Soverx::SHA256(message);
    
    // Sign the hash
    Soverx::Signature sig = kp.sign(msgHash);
    
    // Signature should not be empty
    EXPECT_GT(sig.size(), 0);
    
    // Verify signature
    bool valid = Soverx::KeyPair::verify(kp.getPublicKey(), msgHash, sig);
    EXPECT_TRUE(valid);
}

// Test: Invalid signature detection
TEST_F(CryptoTest, InvalidSignatureDetection) {
    Soverx::KeyPair kp1, kp2;
    
    std::string message = "Test message";
    Soverx::RandomXHash msgHash = Soverx::SHA256(message);
    
    // Sign with kp1
    Soverx::Signature sig = kp1.sign(msgHash);
    
    // Try to verify with kp2's public key (should fail)
    bool valid = Soverx::KeyPair::verify(kp2.getPublicKey(), msgHash, sig);
    EXPECT_FALSE(valid);
}

// Test: Address derivation consistency
TEST_F(CryptoTest, AddressDerivation) {
    Soverx::KeyPair kp;
    
    // Derive address from public key
    std::string derivedAddr = Soverx::KeyPair::deriveAddress(kp.getPublicKey());
    
    // Should match KeyPair's address
    EXPECT_EQ(derivedAddr, kp.getAddress());
}

// Test: SHA256 consistency
TEST_F(CryptoTest, SHA256Consistency) {
    std::string message = "Soverx Blockchain";
    
    // Same input should produce same hash
    Soverx::RandomXHash hash1 = Soverx::SHA256(message);
    Soverx::RandomXHash hash2 = Soverx::SHA256(message);
    
    EXPECT_EQ(hash1, hash2);
    
    // Different input should produce different hash
    Soverx::RandomXHash hash3 = Soverx::SHA256("Different message");
    EXPECT_NE(hash1, hash3);
}
