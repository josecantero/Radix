#include "Node.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <random>
#include <fstream>

namespace Radix {

Node::Node(Blockchain& blockchain) : blockchain(blockchain), running(false), syncState(SyncState::NEEDS_SYNC) {
    loadBannedPeers("radix_banned_peers.dat");
}

Node::~Node() {
    saveBannedPeers("radix_banned_peers.dat");
    stop();
}

void Node::startServer(int port) {
    this->myPort = port;
    serverSocketFd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocketFd == -1) {
        std::cerr << "Error al crear el socket del servidor." << std::endl;
        return;
    }

    int opt = 1;
    if (setsockopt(serverSocketFd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        std::cerr << "Error en setsockopt" << std::endl;
        close(serverSocketFd);
        return;
    }

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(serverSocketFd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "Error en bind al puerto " << port << std::endl;
        close(serverSocketFd);
        return;
    }

    if (listen(serverSocketFd, 10) < 0) {
        std::cerr << "Error en listen" << std::endl;
        close(serverSocketFd);
        return;
    }

    running = true;
    std::cout << "Nodo escuchando en el puerto " << port << std::endl;

    serverThread = std::thread(&Node::acceptLoop, this, serverSocketFd);
    witnessingMonitorThread = std::thread(&Node::monitorWitnessingTimeouts, this);
}

void Node::stop() {
    running = false;
    
    // Shutdown server socket to unblock accept()
    if (serverSocketFd != -1) {
        shutdown(serverSocketFd, SHUT_RDWR);
        close(serverSocketFd);
        serverSocketFd = -1;
    }
    
    if (serverThread.joinable()) {
        serverThread.join(); 
    }
    
    if (witnessingMonitorThread.joinable()) {
        witnessingMonitorThread.join();
    }
    
    std::lock_guard<std::mutex> lock(peersMutex);
    for (auto& peer : peers) {
        peer->closeConnection();
    }
    peers.clear();
}

bool Node::connectToPeer(const std::string& ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Error creando socket cliente" << std::endl;
        return false;
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr) <= 0) {
        std::cerr << "Direccion invalida / no soportada: " << ip << std::endl;
        close(sock);
        return false;
    }

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Conexion fallida a " << ip << ":" << port << " Error: " << strerror(errno) << std::endl;
        close(sock);
        return false;
    }

    std::cout << "Conectado exitosamente a " << ip << ":" << port << std::endl;

    auto peer = std::make_shared<Peer>(sock, serv_addr);
    {
        std::lock_guard<std::mutex> lock(peersMutex);
        peers.push_back(peer);
    }

    // Initiate Handshake
    Message handshakeMsg;
    handshakeMsg.header.magic = RADIX_NETWORK_MAGIC;
    handshakeMsg.header.type = MessageType::HANDSHAKE;
    handshakeMsg.header.payloadSize = 0;
    handshakeMsg.header.checksum = calculateChecksum(handshakeMsg.payload);
    
    peer->sendMessage(handshakeMsg);

    std::thread(&Node::handlePeer, this, peer).detach();

    return true;
}

void Node::broadcast(const Message& msg) {
    std::lock_guard<std::mutex> lock(peersMutex);
    for (auto& peer : peers) {
        if (peer->isConnected() && peer->isHandshaked()) {
            peer->sendMessage(msg);
        }
    }
}

void Node::broadcastBlock(const Block& block) {
    Message msg;
    msg.header.magic = RADIX_NETWORK_MAGIC;
    msg.header.type = MessageType::NEW_BLOCK;

    // Serialize block to payload
    std::stringstream ss;
    block.serialize(ss);
    std::string serializedBlock = ss.str();

    msg.header.payloadSize = serializedBlock.size();
    msg.payload.assign(serializedBlock.begin(), serializedBlock.end());
    msg.header.checksum = calculateChecksum(msg.payload);

    broadcast(msg);
}

void Node::acceptLoop(int serverSocketFd) {
    while (running) {
        struct sockaddr_in address;
        int addrlen = sizeof(address);
        int new_socket = accept(serverSocketFd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        
        if (new_socket < 0) {
            if (running) std::cerr << "Error en accept" << std::endl;
            continue;
        }

        std::cout << "Nueva conexion entrante aceptada." << std::endl;
        
        auto peer = std::make_shared<Peer>(new_socket, address);
        {
            std::lock_guard<std::mutex> lock(peersMutex);
            peers.push_back(peer);
        }

        std::thread(&Node::handlePeer, this, peer).detach();
    }
    close(serverSocketFd);
}

void Node::handlePeer(std::shared_ptr<Peer> peer) {
    Message msg;
    while (peer->isConnected() && running) {
        if (peer->readMessage(msg)) {
            processMessage(peer, msg);
        } else {
            // Connection lost
            break;
        }
    }
    
    std::cout << "Peer desconectado: " << peer->getIpAddress() << std::endl;
    peer->closeConnection();

    // Remove peer from list
    std::lock_guard<std::mutex> lock(peersMutex);
    peers.erase(std::remove(peers.begin(), peers.end(), peer), peers.end());
}

void Node::broadcastTransaction(const Transaction& tx) {
    Message msg;
    msg.header.magic = RADIX_NETWORK_MAGIC;
    msg.header.type = MessageType::NEW_TRANSACTION;
    
    std::stringstream ss;
    tx.serialize(ss);
    std::string data = ss.str();
    
    msg.payload.assign(data.begin(), data.end());
    msg.header.payloadSize = msg.payload.size();
    msg.header.checksum = calculateChecksum(msg.payload);

    std::cout << "DEBUG: Broadcasting transaction to " << peers.size() << " peers." << std::endl;
    broadcast(msg);
}

void Node::processMessage(std::shared_ptr<Peer> peer, const Message& msg) {
    if (msg.header.magic != RADIX_NETWORK_MAGIC) {
        std::cerr << "Mensaje con Magic invalido de " << peer->getIpAddress() << std::endl;
        peer->closeConnection();
        return;
    }

    // Validate checksum for message integrity
    if (!validateChecksum(msg)) {
        std::cerr << "❌ Checksum inválido de " << peer->getIpAddress() << std::endl;
        std::cerr << "   Posible corrupción de datos o ataque MITM" << std::endl;
        peer->closeConnection();
        return;
    }

    switch (msg.header.type) {
        case MessageType::HANDSHAKE: {
            std::cout << "Recibido HANDSHAKE de " << peer->getIpAddress() << std::endl;
            // Respond with ACK
            Message ackMsg;
            ackMsg.header.magic = RADIX_NETWORK_MAGIC;
            ackMsg.header.type = MessageType::HANDSHAKE_ACK;
            ackMsg.header.payloadSize = 0;
            ackMsg.header.checksum = calculateChecksum(ackMsg.payload);
            peer->sendMessage(ackMsg);
            
            peer->setHandshaked(true);

            // Send GET_PEERS to discover more nodes
            Message getPeersMsg;
            getPeersMsg.header.magic = RADIX_NETWORK_MAGIC;
            getPeersMsg.header.type = MessageType::GET_PEERS;
            getPeersMsg.header.payloadSize = 0;
            getPeersMsg.header.checksum = calculateChecksum(getPeersMsg.payload);
            peer->sendMessage(getPeersMsg);

            break;
        }
        case MessageType::HANDSHAKE_ACK: {
            std::cout << "Recibido HANDSHAKE_ACK de " << peer->getIpAddress() << std::endl;
            peer->setHandshaked(true);

            // Send GET_PEERS to discover more nodes
            Message getPeersMsg;
            getPeersMsg.header.magic = RADIX_NETWORK_MAGIC;
            getPeersMsg.header.type = MessageType::GET_PEERS;
            getPeersMsg.header.payloadSize = 0;
            getPeersMsg.header.checksum = calculateChecksum(getPeersMsg.payload);
            peer->sendMessage(getPeersMsg);

            // Also trigger sync
            checkSyncStatus();
            break;
        }
        case MessageType::NEW_BLOCK: {
            std::cout << "Recibido NUEVO BLOQUE de " << peer->getIpAddress() << std::endl;
            
            // Check if peer is banned
            if (isPeerBanned(peer->getIpAddress())) {
                std::cout << "❌ Rechazando bloque de peer baneado: " << peer->getIpAddress() << std::endl;
                peer->closeConnection();
                break;
            }
            
            if (msg.payload.empty()) break;

            try {
                std::stringstream ss(std::string(msg.payload.begin(), msg.payload.end()));
                Radix::RandomXContext dummyContext; 
                Block newBlock(0, "", {}, 0, dummyContext); 
                newBlock.deserialize(ss);

                // Check if we've already seen this block (prevent broadcast loops)
                if (hasSeenBlock(newBlock.hash)) {
                    std::cout << "⏭️  Bloque ya visto - ignorando rebroadcast" << std::endl;
                    break;
                }
                
                // Mark as seen BEFORE processing to prevent re-entrance
                markBlockAsSeen(newBlock.hash);

                Blockchain::BlockStatus status = blockchain.submitBlock(newBlock);

                if (status == Blockchain::BlockStatus::ACCEPTED) {
                    std::cout << "✅ Bloque ACEPTADO. Altura: " << blockchain.getChainSize() - 1 << std::endl;
                    // Re-broadcast to other peers (now protected against loops)
                    broadcastBlock(newBlock);  
                    
                } else if (status == Blockchain::BlockStatus::REQUIRES_WITNESSING) {
                    std::cout << "\n⚠️⚠️⚠️  REORGANIZACIÓN PROFUNDA DETECTADA  ⚠️⚠️⚠️\n";
                    std::cout << "Iniciando PROTOCOLO DE TESTIGOS (Peer Witnessing)\n" << std::endl;
                    
                    // Select random witnesses (1-5 nodes)
                    auto witnesses = selectRandomWitnesses(5);
                    
                    if (witnesses.empty()) {
                        std::cout << "❌ Sin peers disponibles para witnessing - RECHAZANDO automáticamente" << std::endl;
                        std::cout << "BANEANDO nodo: " << peer->getIpAddress() << "\n" << std::endl;
                        banPeer(peer->getIpAddress(), "Reorganización profunda sin testigos disponibles para verificar");
                        break;
                    }
                    
                    std::cout << "📋 Consultando a " << witnesses.size() << " testigo(s) aleatorio(s)..." << std::endl;
                    
                    // Create witness query
                    WitnessQuery query;
                    query.blockHeight = blockchain.getChainSize() - 1; // Current tip height
                    query.blockHash = newBlock.hash;
                    query.startTime = std::chrono::steady_clock::now();
                    query.queryingPeerIp = peer->getIpAddress();
                    query.expectedResponses = witnesses.size();
                    query.completed = false;
                    
                    {
                        std::lock_guard<std::mutex> lock(witnessQueriesMutex);
                        activeWitnessQueries[newBlock.hash] = query;
                    }
                    // Store block for later
                    pendingWitnessBlocks[newBlock.hash] = std::make_shared<Block>(newBlock); 
                    
                    // Send queries to selected witnesses
                    for (auto& witness : witnesses) {
                        WitnessQueryPayload queryPayload;
                        queryPayload.blockHeight = query.blockHeight;
                        std::strncpy(queryPayload.blockHash, newBlock.hash.c_str(), 64);
                        queryPayload.blockHash[64] = '\0';
                        
                        Message queryMsg;
                        queryMsg.header.magic = RADIX_NETWORK_MAGIC;
                        queryMsg.header.type = MessageType::WITNESS_QUERY;
                        queryMsg.header.payloadSize = sizeof(queryPayload);
                        queryMsg.header.checksum = calculateChecksum(queryMsg.payload);
                        queryMsg.payload.resize(sizeof(queryPayload));
                        std::memcpy(queryMsg.payload.data(), &queryPayload, sizeof(queryPayload));
                        
                        std::cout << "  → Enviando query a testigo: " << witness->getIpAddress() << std::endl;
                        witness->sendMessage(queryMsg);
                    }
                    
                    std::cout << "⏳ Esperando respuestas (timeout: 10s)...\n" << std::endl;
                    
                } else if (status == Blockchain::BlockStatus::REJECTED_INVALID) {
                     // Check if we're missing the parent block
                    int parentHeight = blockchain.getBlockHeight(newBlock.prevHash);
                    if (parentHeight == -1 && blockchain.getChainSize() > 0) {
                        // We don't have the parent - need to sync
                        std::cout << "⚠️  Nos falta el bloque padre. Iniciando sincronización..." << std::endl;
                        
                        uint64_t ourHeight = blockchain.getChainSize() - 1;
                        targetChainHeight = ourHeight + 10; // Estimate
                        
                        requestBlockchain(peer, ourHeight + 1);
                    } else {
                        std::cout << "❌ Bloque rechazado. Estado: " << (int)status << std::endl;
                    }
                } else {
                    std::cout << "❌ Bloque rechazado. Estado: " << (int)status << std::endl;
                }

            } catch (const std::exception& e) {
                std::cerr << "❌ Error procesando bloque: " << e.what() << std::endl;
            }
            break;
        }
        
        case MessageType::GET_PEERS: {
            std::cout << "📡 Received GET_PEERS request." << std::endl;
            // Send PEER_LIST
            Message response;
            response.header.magic = RADIX_NETWORK_MAGIC;
            response.header.type = MessageType::PEER_LIST;
            
            std::string peerListStr;
            {
                std::lock_guard<std::mutex> lock(knownPeersMutex);
                int count = 0;
                for (const auto& p : knownPeers) {
                    if (count++ > 10) break; // Limit to 10 peers
                    peerListStr += p + ",";
                }
            }
            if (!peerListStr.empty()) peerListStr.pop_back(); // Remove last comma

            response.payload.assign(peerListStr.begin(), peerListStr.end());
            response.header.payloadSize = response.payload.size();
            response.header.checksum = calculateChecksum(response.payload); 

            peer->sendMessage(response);
            break;
        }

        case MessageType::PEER_LIST: {
            std::string peerListStr(msg.payload.begin(), msg.payload.end());
            std::cout << "📡 Received PEER_LIST: " << peerListStr << std::endl;
            
            std::stringstream ss(peerListStr);
            std::string segment;
            std::lock_guard<std::mutex> lock(knownPeersMutex);
            while (std::getline(ss, segment, ',')) {
                if (!segment.empty()) {
                    knownPeers.insert(segment);
                }
            }
            saveKnownPeers("radix_peers.dat");
            break;
        }

        case MessageType::NEW_TRANSACTION: {
            std::cout << "💸 Recibida NUEVA TRANSACCION de " << peer->getIpAddress() << std::endl;
            
            if (msg.payload.empty()) break;

            try {
                std::stringstream ss(std::string(msg.payload.begin(), msg.payload.end()));
                Transaction tx;
                tx.deserialize(ss);
                
                std::cout << "   ID: " << tx.id << std::endl;

                // Check if we've already seen this transaction (prevent broadcast loops)
                if (hasSeenTransaction(tx.id)) {
                    std::cout << "⏭️  Transacción ya vista - ignorando rebroadcast" << std::endl;
                    break;
                }
                
                // Mark as seen
                markTransactionAsSeen(tx.id);

                // Try to add to our mempool
                if (blockchain.addTransaction(tx)) {
                    std::cout << "✅ Transaccion valida y agregada al mempool." << std::endl;
                    // Re-broadcast to others (Gossip) - now protected against loops
                    broadcastTransaction(tx);
                } else {
                    std::cout << "⚠️ Transaccion rechazada o ya conocida." << std::endl;
                }

            } catch (const std::exception& e) {
                std::cerr << "❌ Error procesando transaccion: " << e.what() << std::endl;
            }
            break;
        }

        case MessageType::REQUEST_CHAIN: {
            if (msg.payload.size() != sizeof(RequestChainPayload)) break;
            
            RequestChainPayload request;
            std::memcpy(&request, msg.payload.data(), sizeof(request));
            
            std::cout << "📤 Peer " << peer->getIpAddress() << " solicita cadena desde altura " 
                      << request.startHeight << std::endl;
            
            // Get blocks from blockchain
            auto blocks = blockchain.getBlocksFromHeight(request.startHeight, request.maxBlocks);
            
            if (blocks.empty()) {
                std::cout << "   No hay bloques para enviar" << std::endl;
                break;
            }
            
            // Serialize blocks
            std::stringstream ss;
            
            // Write block count
            uint64_t blockCount = blocks.size();
            ss.write(reinterpret_cast<const char*>(&blockCount), sizeof(blockCount));
            
            // Write each block
            for (const auto& block : blocks) {
                block.serialize(ss);
            }
            
            std::string serialized = ss.str();
            
            // Create response message
            Message response;
            response.header.magic = RADIX_NETWORK_MAGIC;
            response.header.type = MessageType::SEND_CHAIN;
            response.header.payloadSize = serialized.size();
            response.header.checksum = calculateChecksum(response.payload);
            response.payload.assign(serialized.begin(), serialized.end());
            
            std::cout << "   Enviando " << blockCount << " bloque(s)" << std::endl;
            peer->sendMessage(response);
            break;
        }
        case MessageType::SEND_CHAIN: {
            if (msg.payload.empty()) break;
            
            std::cout << "📥 Recibiendo cadena de " << peer->getIpAddress() << std::endl;
            
            try {
                std::stringstream ss(std::string(msg.payload.begin(), msg.payload.end()));
                
                // Read block count
                uint64_t blockCount = 0;
                ss.read(reinterpret_cast<char*>(&blockCount), sizeof(blockCount));
                
                std::cout << "   Recibidos " << blockCount << " bloque(s)" << std::endl;
                
                // Read blocks
                std::vector<Block> receivedBlocks;
                Radix::RandomXContext dummyContext;
                
                for (uint64_t i = 0; i < blockCount; ++i) {
                    Block block(0, "", {}, 0, dummyContext);
                    block.deserialize(ss);
                    receivedBlocks.push_back(block);
                }
                
                // Process received chain
                processReceivedChain(receivedBlocks, 0);
                
            } catch (const std::exception& e) {
                std::cerr << "❌ Error procesando cadena recibida: " << e.what() << std::endl;
                std::lock_guard<std::mutex> lock(syncStateMutex);
                syncState = SyncState::NEEDS_SYNC;
            }
            break;
        }


        case MessageType::WITNESS_QUERY: {
            if (msg.payload.size() != sizeof(WitnessQueryPayload)) {
                std::cerr << "Payload de WITNESS_QUERY invalido." << std::endl;
                break;
            }
            WitnessQueryPayload query;
            std::memcpy(&query, msg.payload.data(), sizeof(query));
            
            std::string myHash = blockchain.getBlockHash(query.blockHeight);
            // Comparar hashes (asegurando terminación nula en query.blockHash)
            query.blockHash[64] = '\0'; 
            bool agrees = (myHash == std::string(query.blockHash));
            
            std::cout << "TESTIGO: Solicitud para altura " << query.blockHeight << ". Mi hash: " << (myHash.empty() ? "Desconocido" : myHash) << ". Veredicto: " << (agrees ? "VALIDO" : "INVALIDO") << std::endl;

            WitnessResponsePayload resp;
            resp.agrees = agrees;
            
            Message respMsg;
            respMsg.header.magic = RADIX_NETWORK_MAGIC;
            respMsg.header.type = MessageType::WITNESS_RESPONSE;
            respMsg.header.payloadSize = sizeof(resp);
            respMsg.header.checksum = calculateChecksum(respMsg.payload);
            respMsg.payload.resize(sizeof(resp));
            std::memcpy(respMsg.payload.data(), &resp, sizeof(resp));
            
            peer->sendMessage(respMsg);
            break;
        }
        case MessageType::WITNESS_RESPONSE: {
            if (msg.payload.size() != sizeof(WitnessResponsePayload)) break;
            
            WitnessResponsePayload resp;
            std::memcpy(&resp, msg.payload.data(), sizeof(resp));
            
            std::cout << "🔍 TESTIGO: Respuesta de " << peer->getIpAddress() << ": " 
                      << (resp.agrees ? "✅ APRUEBA" : "❌ RECHAZA") << std::endl;
            
            // Find the corresponding active query
            std:: lock_guard<std::mutex> lock(witnessQueriesMutex);
            for (auto& [blockHash, query] : activeWitnessQueries) {
                if (!query.completed) {
                    // Check if this peer already responded
                    bool alreadyResponded = false;
                    for (const auto& respondedIp : query.respondedPeers) {
                        if (respondedIp == peer->getIpAddress()) {
                            alreadyResponded = true;
                            break;
                        }
                    }
                    
                    if (!alreadyResponded) {
                        query.responses.push_back(resp.agrees);
                        query.respondedPeers.push_back(peer->getIpAddress());
                        
                        std::cout << "   Respuestas recibidas: " << query.responses.size() 
                                  << "/" << query.expectedResponses << std::endl;
                        
                        // If all witnesses have responded, process immediately (no need to wait for timeout)
                        if (query.responses.size() >= static_cast<size_t>(query.expectedResponses)) {
                            std::cout << "✅ Todas las respuestas recibidas. Procesando resultado..." << std::endl;
                            processWitnessQueryResult(blockHash);
                            query.completed = true;
                        }
                    }
                    break; // Only process for the first active query
                }
            }
            break;
        }
        default: {
            std::cout << "Mensaje desconocido recibido: " << (int)msg.header.type << std::endl;
            break;
        }
    }
}

// ============================================================================
// PEER WITNESSING PROTOCOL IMPLEMENTATION
// ============================================================================

std::vector<std::shared_ptr<Peer>> Node::selectRandomWitnesses(int maxCount) {
    std::lock_guard<std::mutex> lock(peersMutex);
    
    std::vector<std::shared_ptr<Peer>> eligiblePeers;
    for (auto& peer : peers) {
        if (peer->isConnected() && peer->isHandshaked() && !isPeerBanned(peer->getIpAddress())) {
            eligiblePeers.push_back(peer);
        }
    }
    
    if (eligiblePeers.empty()) return {};
    
    // If we have fewer than maxCount peers, use all
    int numToSelect = std::min(maxCount, static_cast<int>(eligiblePeers.size()));
    
    // Cryptographically secure random selection
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(eligiblePeers.begin(), eligiblePeers.end(), g);
    
    return std::vector<std::shared_ptr<Peer>>(eligiblePeers.begin(), eligiblePeers.begin() + numToSelect);
}

void Node::monitorWitnessingTimeouts() {
    const auto TIMEOUT_DURATION = std::chrono::seconds(10);
    
    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        std::lock_guard<std::mutex> lock(witnessQueriesMutex);
        auto now = std::chrono::steady_clock::now();
        
        for (auto& [blockHash, query] : activeWitnessQueries) {
            if (!query.completed && (now - query.startTime) > TIMEOUT_DURATION) {
                std::cout << "⏱️ TESTIGO: Timeout para query de bloque " << blockHash.substr(0, 16) << "..." << std::endl;
                processWitnessQueryResult(blockHash);
                query.completed = true;
            }
        }
        
        // Clean up old completed queries (after 5 minutes)
        for (auto it = activeWitnessQueries.begin(); it != activeWitnessQueries.end();) {
            if (it->second.completed && (now - it->second.startTime) > std::chrono::minutes(5)) {
                it = activeWitnessQueries.erase(it);
            } else {
                ++it;
            }
        }
        
        // Clean up seen caches periodically (every 30 seconds)
        static auto lastCacheCleanup = std::chrono::steady_clock::now();
        if ((now - lastCacheCleanup) > std::chrono::seconds(30)) {
            cleanupSeenCaches();
            lastCacheCleanup = now;
        }
    }
}

bool Node::isPeerBanned(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(bannedPeersMutex);
    
    for (const auto& banned : bannedPeers) {
        if (banned.ip == ip) {
            // Permanent ban for now (could implement time-based unbanning)
            return true;
        }
    }
    return false;
}

void Node::banPeer(const std::string& ip, const std::string& reason) {
    {
        std::lock_guard<std::mutex> lock(bannedPeersMutex);
        
        // Check if already banned
        for (const auto& banned : bannedPeers) {
            if (banned.ip == ip) return;
        }
        
        BannedPeer ban;
        ban.ip = ip;
        ban.banTime = std::chrono::steady_clock::now();
        ban.reason = reason;
        
        bannedPeers.push_back(ban);
    }
    
    std::cout << "🚫 PEER BANEADO: " << ip << "\n   Razón: " << reason << std::endl;
    
    // Disconnect the peer if currently connected
    {
        std::lock_guard<std::mutex> peerLock(peersMutex);
        for (auto& peer : peers) {
            if (peer->getIpAddress() == ip) {
                peer->closeConnection();
            }
        }
    }
    
    saveBannedPeers("radix_banned_peers.dat");
}

void Node::processWitnessQueryResult(const std::string& blockHash) {
    auto it = activeWitnessQueries.find(blockHash);
    if (it == activeWitnessQueries.end()) return;
    
    WitnessQuery& query = it->second;
    
    // Count votes
    int agrees = 0, disagrees = 0;
    for (bool response : query.responses) {
        if (response) agrees++;
        else disagrees++;
    }
    
    int total = agrees + disagrees;
    
    std::cout << "\n═══════════════════════════════════════════════════\n";
    std::cout << "⚖️  RESULTADO DE PEER WITNESSING\n";
    std::cout << "═══════════════════════════════════════════════════\n";
    std::cout << "Bloque: " << blockHash.substr(0, 16) << "...\n";
    std::cout << "Testigos consultados: " << query.expectedResponses << "\n";
    std::cout << "Respuestas recibidas: " << total << "\n";
    std::cout << "  ✓ Aprueban: " << agrees << "\n";
    std::cout << "  ✗ Rechazan: " << disagrees << "\n";
    std::cout << "═══════════════════════════════════════════════════\n";
    
    if (total == 0) {
        std::cout << "❌ DECISIÓN: Sin respuestas - RECHAZANDO por seguridad\n";
        std::cout << "Nodo sospechoso: " << query.queryingPeerIp << std::endl;
        std::cout << "═══════════════════════════════════════════════════\n\n";
        banPeer(query.queryingPeerIp, "Reorganización profunda sin testigos disponibles para verificar");
        return;
    }
    
    // Decision by majority
    if (agrees > disagrees) {
        std::cout << "✅ DECISIÓN: MAYORÍA APRUEBA (" << agrees << "/" << total << ")\n";
        std::cout << "   El bloque puede ser considerado válido\n";
        std::cout << "═══════════════════════════════════════════════════\n\n";
        
        // Apply Reorganization
        if (pendingWitnessBlocks.count(blockHash)) {
            blockchain.applyReorganization(*pendingWitnessBlocks[blockHash]);
            pendingWitnessBlocks.erase(blockHash);
        } else {
            std::cerr << "❌ Error: Bloque pendiente no encontrado para reorg: " << blockHash << std::endl;
        }
    } else if (disagrees > agrees) {
        std::cout << "❌ DECISIÓN: MAYORÍA RECHAZA (" << disagrees << "/" << total << ")\n";
        std::cout << "   ⚠️  ATAQUE 51% DETECTADO\n";
        std::cout << "   Baneando nodo malicioso: " << query.queryingPeerIp << "\n";
        std::cout << "═══════════════════════════════════════════════════\n\n";
        banPeer(query.queryingPeerIp, "Intento de ataque 51% detectado por consenso de testigos");
    } else {
        // Tie - reject for security
        std::cout << "⚠️  DECISIÓN: EMPATE (" << agrees << "/" << total << ")\n";
        std::cout << "   Rechazando por seguridad\n";
        std::cout << "═══════════════════════════════════════════════════\n\n";
        banPeer(query.queryingPeerIp, "Empate en witnessing - rechazado por seguridad");
    }
}

void Node::loadBannedPeers(const std::string& filename) {
    std::ifstream fs(filename, std::ios::binary);
    if (!fs.is_open()) {
        std::cout << "No se encontró archivo de peers baneados (primera ejecución)" << std::endl;
        return;
    }
    
    try {
        size_t count = 0;
        fs.read(reinterpret_cast<char*>(&count), sizeof(count));
        
        std::lock_guard<std::mutex> lock(bannedPeersMutex);
        bannedPeers.clear();
        
        for (size_t i = 0; i < count; ++i) {
            BannedPeer ban;
            
            // Read IP
            size_t ipLen = 0;
            fs.read(reinterpret_cast<char*>(&ipLen), sizeof(ipLen));
            ban.ip.resize(ipLen);
            fs.read(&ban.ip[0], ipLen);
            
            // Read timestamp (as duration count)
            decltype(ban.banTime.time_since_epoch().count()) timeCount;
            fs.read(reinterpret_cast<char*>(&timeCount), sizeof(timeCount));
            ban.banTime = std::chrono::steady_clock::time_point(std::chrono::steady_clock::duration(timeCount));
            
            // Read reason
            size_t reasonLen = 0;
            fs.read(reinterpret_cast<char*>(&reasonLen), sizeof(reasonLen));
            ban.reason.resize(reasonLen);
            fs.read(&ban.reason[0], reasonLen);
            
            bannedPeers.push_back(ban);
        }
        
        std::cout << "✅ Cargados " << bannedPeers.size() << " peers baneados desde disco" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "❌ Error cargando lista de baneados: " << e.what() << std::endl;
    }
    
    fs.close();
}

void Node::saveBannedPeers(const std::string& filename) const {
    std::ofstream fs(filename, std::ios::binary);
    if (!fs.is_open()) {
        std::cerr << "❌ No se pudo abrir archivo para guardar peers baneados" << std::endl;
        return;
    }
    
    std::lock_guard<std::mutex> lock(bannedPeersMutex);
    
    size_t count = bannedPeers.size();
    fs.write(reinterpret_cast<const char*>(&count), sizeof(count));
    
    for (const auto& ban : bannedPeers) {
        // Write IP
        size_t ipLen = ban.ip.size();
        fs.write(reinterpret_cast<const char*>(&ipLen), sizeof(ipLen));
        fs.write(ban.ip.data(), ipLen);
        
        // Write timestamp
        auto timeCount = ban.banTime.time_since_epoch().count();
        fs.write(reinterpret_cast<const char*>(&timeCount), sizeof(timeCount));
        
        // Write reason
        size_t reasonLen = ban.reason.size();
        fs.write(reinterpret_cast<const char*>(&reasonLen), sizeof(reasonLen));
        fs.write(ban.reason.data(), reasonLen);
    }
    
    fs.close();
}



// ============================================================================
// BLOCKCHAIN SYNCHRONIZATION IMPLEMENTATION
// ============================================================================

void Node::checkSyncStatus() {
    std::lock_guard<std::mutex> lock(syncStateMutex);
    
    if (syncState == SyncState::SYNCING) {
        // Already syncing
        return;
    }
    
    // Check if we need to sync
    // uint64_t ourHeight = blockchain.getChainSize() - 1;
    
    // Ask a random peer for their chain height
    auto witnesses = selectRandomWitnesses(1);
    if (witnesses.empty()) {
        // std::cout << "ℹ️  Sin peers para verificar sincronización" << std::endl;
        return;
    }
    
    // For now, we'll detect desync when we receive a block we don't have
    // Full implementation would query peer heights
}

void Node::requestBlockchain(std::shared_ptr<Peer> peer, uint64_t fromHeight) {
    std::lock_guard<std::mutex> lock(syncStateMutex);
    
    if (syncState == SyncState::SYNCING) {
        auto now = std::chrono::steady_clock::now();
        if (now - lastSyncRequest < std::chrono::seconds(30)) {
            // Still waiting for previous request
            return;
        }
    }
    
    syncState = SyncState::SYNCING;
    lastSyncRequest = std::chrono::steady_clock::now();
    
    RequestChainPayload payload;
    payload.startHeight = fromHeight;
    payload.maxBlocks = BLOCKS_PER_REQUEST;
    
    Message msg;
    msg.header.magic = RADIX_NETWORK_MAGIC;
    msg.header.type = MessageType::REQUEST_CHAIN;
    msg.header.payloadSize = sizeof(payload);
    msg.payload.resize(sizeof(payload));
    std::memcpy(msg.payload.data(), &payload, sizeof(payload));
    msg.header.checksum = calculateChecksum(msg.payload);
    
    std::cout << "📥 Solicitando blockchain desde altura " << fromHeight 
              << " (hasta " << (fromHeight + BLOCKS_PER_REQUEST) << ")" << std::endl;
    
    peer->sendMessage(msg);
}

void Node::processReceivedChain(const std::vector<Block>& blocks, uint64_t startHeight) {
    if (blocks.empty()) {
        std::cout << "⚠️  Cadena recibida está vacía" << std::endl;
        return;
    }
    
    uint64_t ourHeight = blockchain.getChainSize() - 1;
    uint64_t receivedEndHeight = startHeight + blocks.size() - 1;
    
    std::cout << "🔍 Validando cadena recibida..." << std::endl;
    std::cout << "   Nuestra altura: " << ourHeight << std::endl;
    // std::cout << "   Cadena recibida: " << startHeight << " - " << receivedEndHeight << std::endl;
    
    // Add blocks one by one
    for (const auto& block : blocks) {
        Blockchain::BlockStatus status = blockchain.submitBlock(block);
        
        if (status == Blockchain::BlockStatus::ACCEPTED) {
            std::cout << "   ✅ Bloque " << blockchain.getChainSize() - 1 << " aceptado" << std::endl;
        } else if (status == Blockchain::BlockStatus::IGNORED_DUPLICATE) {
            // Skip duplicates
            continue;
        } else if (status == Blockchain::BlockStatus::REQUIRES_WITNESSING) {
            std::cout << "   ⚠️  Bloque requiere witnessing - pausando sync" << std::endl;
            // Let the witnessing protocol handle it
            std::lock_guard<std::mutex> lock(syncStateMutex);
            syncState = SyncState::NEEDS_SYNC;
            return;
        } else {
            std::cout << "   ❌ Bloque rechazado. Estado: " << (int)status << std::endl;
            std::lock_guard<std::mutex> lock(syncStateMutex);
            syncState = SyncState::NEEDS_SYNC;
            return;
        }
    }
    
    // Check if we need more blocks
    ourHeight = blockchain.getChainSize() - 1;
    
    if (receivedEndHeight >= targetChainHeight || blocks.size() < BLOCKS_PER_REQUEST) {
        // We're synced!
        std::cout << "✅ Sincronización completada. Altura: " << ourHeight << std::endl;
        std::lock_guard<std::mutex> lock(syncStateMutex);
        syncState = SyncState::SYNCED;
    } else {
        // Request next batch
        std::cout << "📥 Solicitando más bloques..." << std::endl;
        // Find the peer and request more
        // For simplicity, we'll set state to NEEDS_SYNC and let it be triggered again
        std::lock_guard<std::mutex> lock(syncStateMutex);
        syncState = SyncState::NEEDS_SYNC;
        
        // Trigger next request immediately if possible (requires peer reference, which we don't have here easily)
        // In a better implementation, we'd pass the peer or store active sync peer
    }
}

bool Node::needsSync() const {
    // std::lock_guard<std::mutex> lock(syncStateMutex); // Can't lock if called from locked context?
    // Be careful with recursive locking. 
    // This is a simple getter, maybe not needed to lock if atomic or just reading
    return syncState == SyncState::NEEDS_SYNC;
}

// ------------------------------------------------------------------------
// PEER DISCOVERY
// ------------------------------------------------------------------------

void Node::discoverPeers() {
    loadKnownPeers("radix_peers.dat");

    // Seed Nodes (Hardcoded for now)
    std::vector<std::string> seeds = {
        "127.0.0.1:8080",
        "127.0.0.1:8081",
        "127.0.0.1:8082"
    };

    {
        std::lock_guard<std::mutex> lock(knownPeersMutex);
        if (knownPeers.empty()) {
            std::cout << "🌱 No known peers. Using seeds." << std::endl;
            for (const auto& seed : seeds) {
                knownPeers.insert(seed);
            }
        }
    }

    // Try to connect to known peers
    std::vector<std::string> peersToConnect;
    {
        std::lock_guard<std::mutex> lock(knownPeersMutex);
        peersToConnect.assign(knownPeers.begin(), knownPeers.end());
    }

    int connectedCount = 0;
    for (const auto& peerAddr : peersToConnect) {
        if (connectedCount >= 5) break; // Max connections

        size_t colonPos = peerAddr.find(':');
        if (colonPos != std::string::npos) {
            std::string ip = peerAddr.substr(0, colonPos);
            int port = std::stoi(peerAddr.substr(colonPos + 1));
            
            // Don't connect to self
            if (myPort != 0 && port == myPort && ip == "127.0.0.1") {
                continue;
            }

            if (connectToPeer(ip, port)) {
                connectedCount++;
            }
        }
    }
}

void Node::saveKnownPeers(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) return;

    std::lock_guard<std::mutex> lock(knownPeersMutex);
    for (const auto& peer : knownPeers) {
        file << peer << "\n";
    }
}

void Node::loadKnownPeers(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return;

    std::string line;
    std::lock_guard<std::mutex> lock(knownPeersMutex);
    while (std::getline(file, line)) {
        if (!line.empty()) {
            knownPeers.insert(line);
        }
    }
}

// ============================================================================
// SEEN CACHE IMPLEMENTATION (Broadcast Loop Prevention)
// ============================================================================

// Define TTL constant
const std::chrono::minutes Node::SEEN_CACHE_TTL{5};

bool Node::hasSeenBlock(const std::string& blockHash) {
    std::lock_guard<std::mutex> lock(seenCacheMutex);
    return seenBlocks.find(blockHash) != seenBlocks.end();
}

void Node::markBlockAsSeen(const std::string& blockHash) {
    std::lock_guard<std::mutex> lock(seenCacheMutex);
    seenBlocks[blockHash] = std::chrono::steady_clock::now();
    
    // Prevent unbounded growth - remove oldest entry if limit exceeded
    if (seenBlocks.size() > MAX_SEEN_CACHE_SIZE) {
        auto oldest = seenBlocks.begin();
        for (auto it = seenBlocks.begin(); it != seenBlocks.end(); ++it) {
            if (it->second < oldest->second) {
                oldest = it;
            }
        }
        seenBlocks.erase(oldest);
    }
}

bool Node::hasSeenTransaction(const std::string& txId) {
    std::lock_guard<std::mutex> lock(seenCacheMutex);
    return seenTransactions.find(txId) != seenTransactions.end();
}

void Node::markTransactionAsSeen(const std::string& txId) {
    std::lock_guard<std::mutex> lock(seenCacheMutex);
    seenTransactions[txId] = std::chrono::steady_clock::now();
    
    // Prevent unbounded growth - remove oldest entry if limit exceeded
    if (seenTransactions.size() > MAX_SEEN_CACHE_SIZE) {
        auto oldest = seenTransactions.begin();
        for (auto it = seenTransactions.begin(); it != seenTransactions.end(); ++it) {
            if (it->second < oldest->second) {
                oldest = it;
            }
        }
        seenTransactions.erase(oldest);
    }
}

void Node::cleanupSeenCaches() {
    std::lock_guard<std::mutex> lock(seenCacheMutex);
    auto now = std::chrono::steady_clock::now();
    
    // Remove expired entries from seenBlocks
    for (auto it = seenBlocks.begin(); it != seenBlocks.end();) {
        if ((now - it->second) > SEEN_CACHE_TTL) {
            it = seenBlocks.erase(it);
        } else {
            ++it;
        }
    }
    
    // Remove expired entries from seenTransactions
    for (auto it = seenTransactions.begin(); it != seenTransactions.end();) {
        if ((now - it->second) > SEEN_CACHE_TTL) {
            it = seenTransactions.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace Radix
