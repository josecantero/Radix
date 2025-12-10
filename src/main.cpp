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
#include "api/ApiKeyManager.h"
#include "config.h"
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
              << "  --config <file>   Cargar configuracion desde archivo JSON (default: config.json)\n"
              << "  --server          Iniciar en modo servidor (nodo)\n"
              << "  --port <port>     Puerto para escuchar (default: 8080)\n"
              << "  --connect <ip:port> Conectar a un peer inicial\n"
              << "  --mine            Habilitar mineria automatica\n"
              << "  --miner-addr <addr> Direccion de recompensa para mineria\n"
              << "  --rpc             Habilitar servidor RPC (default: 8090)\n"
              << "  --rpc-genkey <name> <file> Generar nueva API Key\n"
              << "  --rpc-listkeys <file>      Listar API Keys existentes\n"
              << "  --rpc-revokekey <key> <file> Revocar una API Key\n"
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

    // 0. Handle API Key Management Commands
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--rpc-genkey" && i + 2 < argc) {
            std::string name = argv[i+1];
            std::string file = argv[i+2];
            std::string key = Radix::ApiKeyManager::createKey(name, file);
            std::cout << "Generated new API Key for '" << name << "': " << key << std::endl;
            std::cout << "Saved to " << file << std::endl;
            return 0;
        }
        else if (std::string(argv[i]) == "--rpc-listkeys" && i + 1 < argc) {
            std::string file = argv[i+1];
            Radix::ApiKeyManager::listKeys(file);
            return 0;
        }
        else if (std::string(argv[i]) == "--rpc-revokekey" && i + 2 < argc) {
            std::string key = argv[i+1];
            std::string file = argv[i+2];
            if (Radix::ApiKeyManager::revokeKey(key, file)) {
                std::cout << "Key revoked successfully." << std::endl;
            } else {
                std::cout << "Key not found or could not be revoked." << std::endl;
            }
            return 0;
        }
    }

    // Load configuration
    std::string configFile = "config.json";
    
    // Check for --config argument first
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            configFile = argv[++i];
            break;
        }
    }
    
    // Load config from file (or defaults if not found)
    Radix::RadixConfig config;
    try {
        config = Radix::ConfigManager::loadFromFile(configFile);
    } catch (const std::exception& e) {
        std::cerr << "❌ Error loading config: " << e.what() << std::endl;
        return 1;
    }
    
    // Override with CLI arguments
    config = Radix::ConfigManager::loadFromArgs(argc, argv, config);
    
    // CLI Commands
    bool newWallet = false;
    std::string walletFile = "";
    bool getBalance = false;
    std::string balanceAddress = "";
    bool sendTx = false;
    uint64_t sendAmount = 0;
    std::string sendRecipient = "";
    std::string sendWalletFile = "";

    // Parse CLI-only commands (not in config file)
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--new-wallet") == 0 && i + 1 < argc) {
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

    if (!config.server_mode && !config.mining_enabled && !config.rpc_enabled) {
        std::cout << "Modo no especificado. Iniciando demo por defecto o usa --help.\n";
        printUsage(argv[0]);
        return 0;
    }

    // Start Node
    Radix::Node node(blockchain);
    
    // Start RPC Server if requested
    std::unique_ptr<Radix::RpcServer> rpcServer;
    if (config.rpc_enabled) {
        rpcServer = std::make_unique<Radix::RpcServer>(blockchain, node);
        rpcServer->configure(
            config.rpc_auth_required,
            config.rpc_keys_file,
            config.rpc_rate_limit,
            config.rpc_rate_limit_auth,
            config.rpc_ip_whitelist
        );
        rpcServer->start(config.rpc_port);
        std::cout << "✅ RPC Server started on port " << config.rpc_port << std::endl;
    }

    if (config.server_mode) {
        std::cout << "Iniciando Radix Node..." << std::endl;
        
        // Start server in a separate thread so we can mine in main thread if needed
        std::thread serverThread([&node, &config]() {
            node.startServer(config.port);
        });
        serverThread.detach();

        // Peer Discovery
        node.discoverPeers();

        if (!config.connect_peer.empty()) {
            size_t colonPos = config.connect_peer.find(':');
            if (colonPos != std::string::npos) {
                std::string ip = config.connect_peer.substr(0, colonPos);
                int p = std::stoi(config.connect_peer.substr(colonPos + 1));
                std::cout << "Conectando a peer " << ip << ":" << p << "..." << std::endl;
                node.connectToPeer(ip, p);
            } else {
                std::cerr << "Formato de peer invalido. Use ip:port" << std::endl;
            }
        }

        if (config.mining_enabled) {
            std::cout << "Mineria habilitada. Minando para: " << config.miner_address << std::endl;
            std::cout << "Nodo corriendo. Presione Ctrl+C para salir." << std::endl;
            
            // Main mining loop
            while (g_running) {
                blockchain.minePendingTransactions(config.miner_address, g_running);
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
    } else if (config.rpc_enabled) { // If only RPC is enabled, but not serverMode
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