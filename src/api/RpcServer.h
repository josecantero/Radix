#ifndef SOVERX_RPC_SERVER_H
#define SOVERX_RPC_SERVER_H

#include "../blockchain.h"
#include "../networking/Node.h"
#include "RateLimiter.h"
#include <thread>
#include <atomic>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <memory>

namespace Soverx {

class RpcServer {
public:
    RpcServer(Blockchain& blockchain, Node& node);
    ~RpcServer();

    void start(int port);
    void stop();
    
    // Configuration
    void configure(bool authRequired, const std::string& keysFile, int rateLimit, int rateLimitAuth, const std::vector<std::string>& whitelist);

private:
    Blockchain& blockchain;
    Node& node;
    std::atomic<bool> running;
    std::thread serverThread;
    int serverSocketFd = -1;

    void acceptLoop(int port);
    void handleConnection(int clientSocket);
    std::string processRequest(const std::string& requestBody);
    
    // RPC Methods
    std::string getBlockCount();
    std::string getBalance(const std::string& address);
    std::string sendTransaction(const std::string& hexTx);

    // Helpers
    std::string createJsonError(int id, int code, const std::string& message);
    std::string createJsonResponse(int id, const std::string& resultJson);
    std::string parseJsonString(const std::string& json, const std::string& key);
    std::vector<std::string> parseJsonArray(const std::string& json, const std::string& key);

    // Auth & Rate Limiting
    void loadApiKeys();
    bool authenticate(const std::string& authHeader);
    bool checkRateLimit(const std::string& identifier, bool isAuthenticated);
    bool isIpWhitelisted(const std::string& ip);
    std::string getClientIp(int clientSocket);
    
    // Auth Members
    std::string keysFile = "rpc_keys.json";
    bool authRequired = true;
    std::vector<std::string> ipWhitelist;
    
    // API Keys cache (key -> info)
    struct ApiKeyCacheEntry {
        std::string name;
        bool revoked;
    };
    std::unordered_map<std::string, ApiKeyCacheEntry> apiKeys;
    std::mutex apiKeysMutex;
    
    // Rate Limiters
    int rateLimit = 100;
    int rateLimitAuth = 1000;
    
    // Map: IP/Token -> RateLimiter
    std::unordered_map<std::string, std::unique_ptr<RateLimiter>> rateLimiters;
    std::mutex rateLimitersMutex;
};

} // namespace Soverx

#endif // SOVERX_RPC_SERVER_H
