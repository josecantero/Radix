#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <cstring>

#include "blockchain.h"
#include "networking/Node.h"
#include "randomx_util.h"
#include "money_util.h"
#include "wallet.h"
#include "api/RpcServer.h"
#include <openssl/provider.h>

void initializeOpenSSL() {
    OSSL_PROVIDER* default_provider = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER* base_provider = OSSL_PROVIDER_load(NULL, "base");
    if (!default_provider || !base_provider) {
        std::cerr << "Advertencia: No se pudieron cargar los proveedores OpenSSL." << std::endl;
    }
}

void printUsage(const char* progName) {
    std::cout << "Uso: " << progName << " [opciones]\n"
              << "Opciones:\n"
              << "  --server          Iniciar en modo servidor (nodo)\n"
              << "  --port <port>     Puerto para escuchar (default: 8080)\n"
              << "  --connect <ip:port> Conectar a un peer inicial\n"
              << "  --mine            Habilitar mineria automatica\n"
              << "  --miner-addr <addr> Direccion de recompensa para mineria\n"
              << "  --rpc             Habilitar servidor RPC (default: 8090)\n"
              << "  --help            Mostrar esta ayuda\n";
}

#include <csignal>
#include <atomic>

std::atomic<bool> g_running(true);

void signalHandler(int signum) {
    std::cout << "\nInterrupcion recibida (" << signum << "). Cerrando..." << std::endl;
    g_running = false;
}

int main(int argc, char* argv[]) {
    initializeOpenSSL();
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    bool serverMode = false;
    int port = 8080;
    std::string connectPeer = "";
    bool mineMode = false; // Renamed from 'mine' to avoid conflict with new 'mine' variable in RPC context
    std::string minerAddress = "radix_miner_default"; 
    bool rpcEnabled = false;
    
    // CLI Commands
    bool newWallet = false;
    std::string walletFile = "";
    bool getBalance = false;
    std::string balanceAddress = "";
    bool sendTx = false;
    uint64_t sendAmount = 0;
    std::string sendRecipient = "";
    std::string sendWalletFile = "";

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--server") == 0) {
            serverMode = true;
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "--connect") == 0 && i + 1 < argc) {
            connectPeer = argv[++i];
            serverMode = true; 
        } else if (strcmp(argv[i], "--mine") == 0) {
            mineMode = true;
        } else if (strcmp(argv[i], "--miner-addr") == 0 && i + 1 < argc) {
            minerAddress = argv[++i];
        } else if (strcmp(argv[i], "--rpc") == 0) {
            rpcEnabled = true;
        } else if (strcmp(argv[i], "--new-wallet") == 0 && i + 1 < argc) {
            newWallet = true;
            walletFile = argv[++i];
        } else if (strcmp(argv[i], "--get-balance") == 0 && i + 1 < argc) {
            getBalance = true;
            balanceAddress = argv[++i];
        } else if (strcmp(argv[i], "--send") == 0 && i + 3 < argc) {
            sendTx = true;
            sendAmount = std::stoull(argv[++i]);
            sendRecipient = argv[++i];
            sendWalletFile = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            printUsage(argv[0]);
            std::cout << "  --new-wallet <file>  Crear nueva wallet y guardar en archivo\n"
                      << "  --get-balance <addr> Consultar saldo de una direccion\n"
                      << "  --send <amount> <dest> <wallet_file> Enviar transaccion\n";
            return 0;
        }
    }

    // Handle CLI Commands first (non-daemon modes)
    if (newWallet) {
        Radix::Wallet wallet;
        wallet.saveToFile(walletFile);
        std::cout << "✅ Nueva wallet creada en: " << walletFile << std::endl;
        std::cout << "   Direccion: " << wallet.getAddress() << std::endl;
        return 0;
    }

    Radix::RandomXContext rxContext;
    Radix::Blockchain blockchain(1, rxContext);
    blockchain.loadChain("radix_blockchain.dat");

    if (getBalance) {
        uint64_t balance = blockchain.getBalanceOfAddress(balanceAddress);
        std::cout << "💰 Balance de " << balanceAddress << ": " << Radix::formatRadsToRDX(balance) << " RDX" << std::endl;
        return 0;
    }

    if (sendTx) {
        try {
            Radix::Wallet wallet(sendWalletFile);
            std::cout << "💸 Creando transaccion..." << std::endl;
            std::cout << "   Desde: " << wallet.getAddress() << std::endl;
            std::cout << "   Para:  " << sendRecipient << std::endl;
            std::cout << "   Monto: " << Radix::formatRadsToRDX(sendAmount) << " RDX" << std::endl;

            Radix::Transaction tx = wallet.createTransaction(sendRecipient, sendAmount, blockchain.getUtxoSet());
            
            std::cout << "✅ Transaccion creada. ID: " << tx.id << std::endl;
            
            // Add to blockchain locally
            if (blockchain.addTransaction(tx)) {
                std::cout << "DEBUG (isValid): Transaccion valida." << std::endl;
                std::cout << "Transaccion " << tx.id << " anadida a la piscina de pendientes." << std::endl;
                
                blockchain.saveChain("radix_blockchain.dat");
                std::cout << "✅ Transaccion guardada en mempool local." << std::endl;

                // Broadcast to network
                std::cout << "📡 Propagando transaccion a la red..." << std::endl;
                Radix::Node node(blockchain);
                node.discoverPeers(); // Connect to seeds/peers
                
                // Give it a moment to connect
                std::this_thread::sleep_for(std::chrono::seconds(1));
                
                node.broadcastTransaction(tx);
                std::cout << "✅ Transaccion enviada a los peers." << std::endl;
                
                // Give it a moment to send before exiting
                std::this_thread::sleep_for(std::chrono::seconds(1));

            } else {
                std::cerr << "❌ Error: La transaccion fue rechazada por la blockchain (posible doble gasto o invalida)." << std::endl;
                return 1;
            }
        } catch (const std::exception& e) {
            std::cerr << "❌ Error enviando transaccion: " << e.what() << std::endl;
            return 1;
        }
        return 0;
    }

    if (!serverMode && !mineMode && !rpcEnabled) {
        std::cout << "Modo no especificado. Iniciando demo por defecto o usa --help.\n";
        printUsage(argv[0]);
        return 0;
    }

    // Start Node
    Radix::Node node(blockchain);
    
    // Start RPC Server if requested
    std::unique_ptr<Radix::RpcServer> rpcServer;
    if (rpcEnabled) {
        rpcServer = std::make_unique<Radix::RpcServer>(blockchain, node);
        rpcServer->start(8090); // Default RPC port
        std::cout << "✅ RPC Server started on port 8090" << std::endl;
    }

    if (serverMode) {
        std::cout << "Iniciando Radix Node..." << std::endl;
        
        // Start server in a separate thread so we can mine in main thread if needed
        std::thread serverThread([&node, port]() {
            node.startServer(port);
        });
        serverThread.detach();

        // Peer Discovery
        node.discoverPeers();

        if (!connectPeer.empty()) {
            size_t colonPos = connectPeer.find(':');
            if (colonPos != std::string::npos) {
                std::string ip = connectPeer.substr(0, colonPos);
                int p = std::stoi(connectPeer.substr(colonPos + 1));
                std::cout << "Conectando a peer " << ip << ":" << p << "..." << std::endl;
                node.connectToPeer(ip, p);
            } else {
                std::cerr << "Formato de peer invalido. Use ip:port" << std::endl;
            }
        }

        if (mineMode) {
            std::cout << "Mineria habilitada. Minando para: " << minerAddress << std::endl;
            std::cout << "Nodo corriendo. Presione Ctrl+C para salir." << std::endl;
            
            // Main mining loop
            while (g_running) {
                blockchain.minePendingTransactions(minerAddress, g_running);
                if (!g_running) break;

                // Broadcast new block
                Radix::Block newBlock = blockchain.getLatestBlock();
                node.broadcastBlock(newBlock);
                
                std::this_thread::sleep_for(std::chrono::seconds(1)); // Throttle
            }
        } else {
            std::cout << "Nodo corriendo en modo solo servidor. Presione Ctrl+C para salir." << std::endl;
            while (g_running) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
        
        std::cout << "Guardando blockchain y cerrando..." << std::endl;
        blockchain.saveChain("radix_blockchain.dat");
        node.stop();
        if (rpcServer) rpcServer->stop();
    } else if (rpcEnabled) { // If only RPC is enabled, but not serverMode
        std::cout << "RPC Server corriendo. Presione Ctrl+C para salir." << std::endl;
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        std::cout << "Guardando blockchain y cerrando..." << std::endl;
        blockchain.saveChain("radix_blockchain.dat");
        if (rpcServer) rpcServer->stop();
    } else { // This case should ideally not be reached if the initial check is correct
        std::cout << "Modo no especificado. Saliendo." << std::endl;
    }

    return 0;
}