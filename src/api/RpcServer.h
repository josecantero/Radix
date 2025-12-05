#ifndef RADIX_RPC_SERVER_H
#define RADIX_RPC_SERVER_H

#include "../blockchain.h"
#include "../networking/Node.h"
#include <thread>
#include <atomic>
#include <string>
#include <vector>

namespace Radix {

class RpcServer {
public:
    RpcServer(Blockchain& blockchain, Node& node);
    ~RpcServer();

    void start(int port);
    void stop();

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
};

} // namespace Radix

#endif // RADIX_RPC_SERVER_H
