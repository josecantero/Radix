#include "RpcServer.h"
#include "ApiKeyManager.h"
#include "../transaction.h"
#include "../logger.h"
#include <iostream>
#include <sstream>
#include <iostream>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>

namespace Soverx {

RpcServer::RpcServer(Blockchain& blockchain, Node& node) 
    : blockchain(blockchain), node(node), running(false) {}

RpcServer::~RpcServer() {
    stop();
}

void RpcServer::configure(bool authRequired, const std::string& keysFile, int rateLimit, int rateLimitAuth, const std::vector<std::string>& whitelist) {
    this->authRequired = authRequired;
    this->keysFile = keysFile;
    this->rateLimit = rateLimit;
    this->rateLimitAuth = rateLimitAuth;
    this->ipWhitelist = whitelist;
}

void RpcServer::start(int port) {
    if (running) return;
    
    // Load API keys if auth is required
    if (authRequired) {
        loadApiKeys();
    }
    
    running = true;
    serverThread = std::thread(&RpcServer::acceptLoop, this, port);
}

void RpcServer::stop() {
    running = false;
    if (serverSocketFd != -1) {
        close(serverSocketFd);
        serverSocketFd = -1;
    }
    if (serverThread.joinable()) {
        serverThread.join();
    }
}

void RpcServer::loadApiKeys() {
    std::lock_guard<std::mutex> lock(apiKeysMutex);
    std::unordered_map<std::string, ApiKeyInfo> keys; // Temporary map to match ApiKeyManager signature
    
    if (ApiKeyManager::loadKeys(keysFile, keys)) {
        apiKeys.clear();
        for (const auto& pair : keys) {
            if (!pair.second.revoked) {
                apiKeys[pair.first] = {pair.second.name, pair.second.revoked};
            }
        }
        LOG_INFO(Logger::api(), "RPC: Loaded {} active API keys", apiKeys.size());
    } else {
        LOG_WARN(Logger::api(), "RPC: No API keys loaded or file not found");
    }
}

void RpcServer::acceptLoop(int port) {
    serverSocketFd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocketFd == -1) {
        LOG_ERROR(Logger::api(), "RPC: Error creating socket");
        return;
    }

    int opt = 1;
    setsockopt(serverSocketFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(serverSocketFd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        LOG_ERROR(Logger::api(), "RPC: Bind failed on port {}", port);
        return;
    }

    if (listen(serverSocketFd, 3) < 0) {
        LOG_ERROR(Logger::api(), "RPC: Listen failed");
        return;
    }

    LOG_INFO(Logger::api(), "RPC Server listening on port {}", port);

    while (running) {
        struct sockaddr_in clientAddr;
        socklen_t addrLen = sizeof(clientAddr);
        int clientSocket = accept(serverSocketFd, (struct sockaddr*)&clientAddr, &addrLen);
        
        if (clientSocket < 0) {
            if (running) LOG_ERROR(Logger::api(), "RPC: Accept failed");
            continue;
        }

        std::thread(&RpcServer::handleConnection, this, clientSocket).detach();
    }
}

std::string RpcServer::getClientIp(int clientSocket) {
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    int res = getpeername(clientSocket, (struct sockaddr *)&addr, &addr_size);
    if (res == 0) {
        char clientip[20];
        inet_ntop(AF_INET, &(addr.sin_addr), clientip, sizeof(clientip));
        return std::string(clientip);
    }
    return "unknown";
}

bool RpcServer::isIpWhitelisted(const std::string& ip) {
    for (const auto& allowedIp : ipWhitelist) {
        if (ip == allowedIp) return true;
    }
    return false;
}

bool RpcServer::authenticate(const std::string& authHeader) {
    if (!authRequired) return true;
    
    // Parse "Bearer <token>" format
    if (authHeader.rfind("Bearer ", 0) != 0) return false;
    std::string token = authHeader.substr(7);
    
    // Check if token exists in our cache
    std::lock_guard<std::mutex> lock(apiKeysMutex);
    auto it = apiKeys.find(token);
    
    if (it != apiKeys.end() && !it->second.revoked) {
        // TODO: Could update last_used timestamp in file asynchronously
        return true;
    }
    
    return false;
}

bool RpcServer::checkRateLimit(const std::string& identifier, bool isAuthenticated) {
    std::lock_guard<std::mutex> lock(rateLimitersMutex);
    
    // Get or create rate limiter for this identifier
    if (rateLimiters.find(identifier) == rateLimiters.end()) {
        int limit = isAuthenticated ? rateLimitAuth : rateLimit;
        rateLimiters[identifier] = std::make_unique<RateLimiter>(limit);
    }
    
    return rateLimiters[identifier]->allowRequest();
}

void RpcServer::handleConnection(int clientSocket) {
    // 1. Get Client IP
    std::string clientIp = getClientIp(clientSocket);
    bool whitelisted = isIpWhitelisted(clientIp);
    
    char buffer[4096] = {0};
    int valread = read(clientSocket, buffer, 4096);
    if (valread <= 0) {
        close(clientSocket);
        return;
    }
    
    std::string request(buffer, valread);
    
    // 2. Parse Headers for Auth
    std::string authToken = "";
    size_t authPos = request.find("Authorization: ");
    if (authPos != std::string::npos) {
        size_t eol = request.find("\r\n", authPos);
        if (eol != std::string::npos) {
            authToken = request.substr(authPos + 15, eol - (authPos + 15));
        }
    }
    
    // 3. Authentication Check
    bool authenticated = false;
    if (whitelisted) {
        authenticated = true;
    } else if (authRequired) {
        if (authenticate(authToken)) {
            authenticated = true;
        } else {
            // 401 Unauthorized
            std::string body = createJsonError(0, -32001, "Unauthorized: Invalid or missing API key");
            std::stringstream response;
            response << "HTTP/1.1 401 Unauthorized\r\n"
                     << "Content-Type: application/json\r\n"
                     << "Content-Length: " << body.length() << "\r\n"
                     << "Connection: close\r\n\r\n"
                     << body;
            std::string resp = response.str();
            send(clientSocket, resp.c_str(), resp.length(), 0);
            close(clientSocket);
            return;
        }
    } else {
        authenticated = true; // Auth disabled
    }
    
    // 4. Rate Limit Check
    // Identifier is auth token if present, else IP
    std::string identifier = (authRequired && !whitelisted && !authToken.empty()) 
                             ? authToken 
                             : clientIp;
                             
    if (!whitelisted && !checkRateLimit(identifier, authRequired && authenticated)) {
        // 429 Too Many Requests
        std::string body = createJsonError(0, -32002, "Rate limit exceeded");
        std::stringstream response;
        response << "HTTP/1.1 429 Too Many Requests\r\n"
                 << "Content-Type: application/json\r\n"
                 << "Content-Length: " << body.length() << "\r\n"
                 << "Connection: close\r\n\r\n"
                 << body;
        std::string resp = response.str();
        send(clientSocket, resp.c_str(), resp.length(), 0);
        close(clientSocket);
        return;
    }

    // 5. Process Request (Existing logic)
    size_t bodyPos = request.find("\r\n\r\n");
    if (bodyPos == std::string::npos) {
        bodyPos = request.find("\n\n");
    }
    
    std::string responseBody;
    if (bodyPos != std::string::npos) {
        std::string body = request.substr(bodyPos + (request.find("\r\n\r\n") != std::string::npos ? 4 : 2));
        responseBody = processRequest(body);
    } else {
        responseBody = createJsonError(0, -32700, "Parse error");
    }
    
    // 200 OK
    std::stringstream response;
    response << "HTTP/1.1 200 OK\r\n"
             << "Content-Type: application/json\r\n"
             << "Content-Length: " << responseBody.length() << "\r\n"
             << "Connection: close\r\n\r\n"
             << responseBody;

    std::string responseStr = response.str();
    send(clientSocket, responseStr.c_str(), responseStr.length(), 0);
    close(clientSocket);
}

std::string RpcServer::processRequest(const std::string& requestBody) {
    // Very basic JSON parsing
    std::string method = parseJsonString(requestBody, "method");
    
    // Extract ID (simple integer parsing)
    int id = 0;
    size_t idPos = requestBody.find("\"id\"");
    if (idPos != std::string::npos) {
        size_t colonPos = requestBody.find(":", idPos);
        if (colonPos != std::string::npos) {
            id = std::atoi(requestBody.c_str() + colonPos + 1);
        }
    }

    if (method == "getblockcount") {
        return createJsonResponse(id, getBlockCount());
    } else if (method == "getbalance") {
        auto params = parseJsonArray(requestBody, "params");
        if (params.empty()) return createJsonError(id, -32602, "Invalid params");
        return createJsonResponse(id, getBalance(params[0]));
    } else if (method == "sendtransaction") {
        auto params = parseJsonArray(requestBody, "params");
        if (params.empty()) return createJsonError(id, -32602, "Invalid params");
        return createJsonResponse(id, sendTransaction(params[0]));
    }

    return createJsonError(id, -32601, "Method not found");
}

std::string RpcServer::getBlockCount() {
    return std::to_string(blockchain.getChainSize());
}

std::string RpcServer::getBalance(const std::string& address) {
    // Remove quotes if present
    std::string cleanAddr = address;
    if (cleanAddr.front() == '"') cleanAddr.erase(0, 1);
    if (cleanAddr.back() == '"') cleanAddr.pop_back();
    
    uint64_t balance = blockchain.getBalanceOfAddress(cleanAddr);

    return std::to_string(balance);
}

std::string RpcServer::sendTransaction(const std::string& hexTx) {
    // Remove quotes if present
    std::string cleanHex = hexTx;
    if (cleanHex.front() == '"') cleanHex.erase(0, 1);
    if (cleanHex.back() == '"') cleanHex.pop_back();

    // Decode hex to bytes
    std::string bytes;
    for (size_t i = 0; i < cleanHex.length(); i += 2) {
        std::string byteString = cleanHex.substr(i, 2);
        char byte = (char)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }

    // Deserialize transaction
    try {
        std::stringstream ss(bytes);
        Transaction tx;
        tx.deserialize(ss);
        
        if (blockchain.addTransaction(tx)) {
            node.broadcastTransaction(tx);
            return "\"" + tx.id + "\"";
        } else {
            return createJsonError(0, -32000, "Transaction rejected");
        }
    } catch (const std::exception& e) {
        return createJsonError(0, -32602, std::string("Deserialization error: ") + e.what());
    }
}

std::string RpcServer::createJsonError(int id, int code, const std::string& message) {
    std::stringstream ss;
    ss << "{\"jsonrpc\": \"2.0\", \"error\": {\"code\": " << code << ", \"message\": \"" << message << "\"}, \"id\": " << id << "}";
    return ss.str();
}

std::string RpcServer::createJsonResponse(int id, const std::string& resultJson) {
    std::stringstream ss;
    ss << "{\"jsonrpc\": \"2.0\", \"result\": " << resultJson << ", \"id\": " << id << "}";
    return ss.str();
}

std::string RpcServer::parseJsonString(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\"";
    size_t keyPos = json.find(searchKey);
    if (keyPos == std::string::npos) return "";

    size_t colonPos = json.find(":", keyPos);
    size_t startQuote = json.find("\"", colonPos);
    if (startQuote == std::string::npos) return "";
    
    size_t endQuote = json.find("\"", startQuote + 1);
    if (endQuote == std::string::npos) return "";

    return json.substr(startQuote + 1, endQuote - startQuote - 1);
}

std::vector<std::string> RpcServer::parseJsonArray(const std::string& json, const std::string& key) {
    std::vector<std::string> result;
    std::string searchKey = "\"" + key + "\"";
    size_t keyPos = json.find(searchKey);
    if (keyPos == std::string::npos) return result;

    size_t startBracket = json.find("[", keyPos);
    size_t endBracket = json.find("]", startBracket);
    
    if (startBracket == std::string::npos || endBracket == std::string::npos) return result;

    std::string arrayContent = json.substr(startBracket + 1, endBracket - startBracket - 1);
    std::stringstream ss(arrayContent);
    std::string segment;
    
    while (std::getline(ss, segment, ',')) {
        // Trim whitespace
        segment.erase(0, segment.find_first_not_of(" \t\n\r"));
        size_t last = segment.find_last_not_of(" \t\n\r");
        if (last != std::string::npos) {
            segment.erase(last + 1);
        }
        result.push_back(segment);
    }
    return result;
}

} // namespace Soverx
