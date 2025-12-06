#ifndef RADIX_NODE_H
#define RADIX_NODE_H

#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <memory>
#include <map>
#include <set>
#include <chrono>
#include "Peer.h"
#include "../blockchain.h"

namespace Radix {

class Node {
public:
    Node(Blockchain& blockchain);
    ~Node();

    // Start the server to listen for incoming connections
    void startServer(int port);
    
    // Connect to another node
    bool connectToPeer(const std::string& ip, int port);
    
    // Stop the node
    void stop();

    // Broadcast a message to all connected peers
    void broadcast(const Message& msg);

    // Broadcast a new block to all connected peers
    void broadcastBlock(const Block& block);

    // Broadcast a new transaction to all connected peers
    void broadcastTransaction(const Transaction& tx);

    // Load/save banned peers list
    void loadBannedPeers(const std::string& filename);
    void saveBannedPeers(const std::string& filename) const;

    // Peer Discovery
    void discoverPeers();
    void saveKnownPeers(const std::string& filename) const;
    void loadKnownPeers(const std::string& filename);

private:
    // Witnessing structures
    struct WitnessQuery {
        uint64_t blockHeight;
        std::string blockHash;
        std::chrono::steady_clock::time_point startTime;
        std::vector<bool> responses;  // true = agrees, false = disagrees
        std::vector<std::string> respondedPeers;  // IPs that already responded
        std::string queryingPeerIp;  // IP of node that sent suspicious block
        int expectedResponses;  // Number of witnesses consulted
        bool completed;
    };

    struct BannedPeer {
        std::string ip;
        std::chrono::steady_clock::time_point banTime;
        std::string reason;
    };

    void acceptLoop(int serverSocketFd);
    void handlePeer(std::shared_ptr<Peer> peer);
    void processMessage(std::shared_ptr<Peer> peer, const Message& msg);

    // Witnessing methods
    std::vector<std::shared_ptr<Peer>> selectRandomWitnesses(int maxCount);
    void monitorWitnessingTimeouts();
    bool isPeerBanned(const std::string& ip) const;
    void banPeer(const std::string& ip, const std::string& reason);
    void processWitnessQueryResult(const std::string& blockHash);

    Blockchain& blockchain;
    std::vector<std::shared_ptr<Peer>> peers;
    std::mutex peersMutex;
    
    // Witnessing state
    std::map<std::string, WitnessQuery> activeWitnessQueries;
    std::map<std::string, std::shared_ptr<Block>> pendingWitnessBlocks; // Blocks waiting for witness approval
    std::mutex witnessQueriesMutex;
    
    std::vector<BannedPeer> bannedPeers;
    mutable std::mutex bannedPeersMutex;

    // Peer Discovery State
    std::set<std::string> knownPeers;
    mutable std::mutex knownPeersMutex;
    
    std::atomic<bool> running;
    std::thread serverThread;
    std::thread witnessingMonitorThread;

    int serverSocketFd = -1; // Initialize to -1
    int myPort = 0; // Port this node is listening on

    // ------------------------------------------------------------------------
    // BLOCKCHAIN SYNCHRONIZATION
    // ------------------------------------------------------------------------
    enum class SyncState {
        SYNCED,           // Blockchain is up to date
        SYNCING,          // Currently downloading blockchain
        NEEDS_SYNC        // Detected need to sync but not started yet
    };

    SyncState syncState = SyncState::NEEDS_SYNC;
    std::mutex syncStateMutex;

    uint64_t targetChainHeight = 0;  // Height we're trying to reach
    std::chrono::steady_clock::time_point lastSyncRequest;

    static const uint64_t BLOCKS_PER_REQUEST = 100;  // Request blocks in batches
    
    // Sync methods
    void checkSyncStatus();
    void requestBlockchain(std::shared_ptr<Peer> peer, uint64_t fromHeight);
    void processReceivedChain(const std::vector<Block>& blocks, uint64_t startHeight);
    bool needsSync() const;

    // ------------------------------------------------------------------------
    // SEEN CACHE (Broadcast Loop Prevention)
    // ------------------------------------------------------------------------
    std::map<std::string, std::chrono::steady_clock::time_point> seenBlocks;
    std::map<std::string, std::chrono::steady_clock::time_point> seenTransactions;
    mutable std::mutex seenCacheMutex;
    
    // Cache configuration
    static const size_t MAX_SEEN_CACHE_SIZE = 1000;
    static const std::chrono::minutes SEEN_CACHE_TTL;
    
    // Cache helper methods
    bool hasSeenBlock(const std::string& blockHash);
    void markBlockAsSeen(const std::string& blockHash);
    bool hasSeenTransaction(const std::string& txId);
    void markTransactionAsSeen(const std::string& txId);
    void cleanupSeenCaches();

};

} // namespace Radix

#endif // RADIX_NODE_H
