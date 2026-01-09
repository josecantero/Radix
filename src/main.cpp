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
#include "logger.h"
#include <openssl/provider.h>

void initializeOpenSSL() {
    OSSL_PROVIDER* default_provider = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER* base_provider = OSSL_PROVIDER_load(NULL, "base");
    if (!default_provider || !base_provider) {
        Soverx::Logger::main()->warn("No se pudieron cargar los proveedores OpenSSL");
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
    Soverx::Logger::main()->info("Interrupcion recibida ({}). Cerrando...", signum);
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
            std::string key = Soverx::ApiKeyManager::createKey(name, file);
            std::cout << "Generated new API Key for '" << name << "': " << key << std::endl;
            std::cout << "Saved to " << file << std::endl;
            return 0;
        }
        else if (std::string(argv[i]) == "--rpc-listkeys" && i + 1 < argc) {
            std::string file = argv[i+1];
            Soverx::ApiKeyManager::listKeys(file);
            return 0;
        }
        else if (std::string(argv[i]) == "--rpc-revokekey" && i + 2 < argc) {
            std::string key = argv[i+1];
            std::string file = argv[i+2];
            if (Soverx::ApiKeyManager::revokeKey(key, file)) {
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
    Soverx::SoverxConfig config;
    try {
        config = Soverx::ConfigManager::loadFromFile(configFile);
    } catch (const std::exception& e) {
        std::cerr << "❌ Error loading config: " << e.what() << std::endl;
        return 1;
    }
    
    // Override with CLI arguments
    config = Soverx::ConfigManager::loadFromArgs(argc, argv, config);
    
    // Initialize Logger with config settings
    Soverx::Logger::init(config.log_dir, config.log_level);
    
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
        Soverx::Wallet wallet;
        wallet.saveToFile(walletFile);
        LOG_INFO(Soverx::Logger::main(), "✅ Nueva wallet creada en: {}", walletFile);
        LOG_INFO(Soverx::Logger::main(), "   Direccion: {}", wallet.getAddress());
        return 0;
    }

    Soverx::RandomXContext rxContext;
    Soverx::Blockchain blockchain(1, rxContext);
    blockchain.loadChain("svx_blockchain.dat");

    if (getBalance) {
        uint64_t balance = blockchain.getBalanceOfAddress(balanceAddress);
        LOG_INFO(Soverx::Logger::main(), "💰 Balance de {}: {} XSV", balanceAddress, Soverx::formatRadsToRDX(balance));
        return 0;
    }

    if (sendTx) {
        try {
            Soverx::Wallet wallet(sendWalletFile);
            LOG_INFO(Soverx::Logger::main(), "💸 Creando transaccion...");
            LOG_INFO(Soverx::Logger::main(), "   Desde: {}", wallet.getAddress());
            LOG_INFO(Soverx::Logger::main(), "   Para:  {}", sendRecipient);
            LOG_INFO(Soverx::Logger::main(), "   Monto: {} XSV", Soverx::formatRadsToRDX(sendAmount));

            Soverx::Transaction tx = wallet.createTransaction(sendRecipient, sendAmount, blockchain.getUtxoSet());
            
            LOG_INFO(Soverx::Logger::main(), "✅ Transaccion creada. ID: {}", tx.id);
            
            // Add to blockchain locally
            if (blockchain.addTransaction(tx)) {
                LOG_DEBUG(Soverx::Logger::main(), "Transaccion valida");
                LOG_INFO(Soverx::Logger::main(), "Transaccion {} anadida a la piscina de pendientes", tx.id);
                
                blockchain.saveChain("svx_blockchain.dat");
                LOG_INFO(Soverx::Logger::main(), "✅ Transaccion guardada en mempool local");

                // Broadcast to network
                LOG_INFO(Soverx::Logger::main(), "📡 Propagando transaccion a la red...");
                Soverx::Node node(blockchain);
                node.discoverPeers(); // Connect to seeds/peers
                
                // Give it a moment to connect
                std::this_thread::sleep_for(std::chrono::seconds(1));
                
                node.broadcastTransaction(tx);
                LOG_INFO(Soverx::Logger::main(), "✅ Transaccion enviada a los peers");
                
                // Give it a moment to send before exiting
                std::this_thread::sleep_for(std::chrono::seconds(1));

            } else {
                LOG_ERROR(Soverx::Logger::main(), "❌ La transaccion fue rechazada por la blockchain (posible doble gasto o invalida)");
                return 1;
            }
        } catch (const std::exception& e) {
            LOG_ERROR(Soverx::Logger::main(), "❌ Error enviando transaccion: {}", e.what());
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
    Soverx::Node node(blockchain);
    
    // Start RPC Server if requested
    std::unique_ptr<Soverx::RpcServer> rpcServer;
    if (config.rpc_enabled) {
        rpcServer = std::make_unique<Soverx::RpcServer>(blockchain, node);
        rpcServer->configure(
            config.rpc_auth_required,
            config.rpc_keys_file,
            config.rpc_rate_limit,
            config.rpc_rate_limit_auth,
            config.rpc_ip_whitelist
        );
        rpcServer->start(config.rpc_port);
        LOG_INFO(Soverx::Logger::main(), "✅ RPC Server started on port {}", config.rpc_port);
    }

    if (config.server_mode) {
        LOG_INFO(Soverx::Logger::main(), "Iniciando Soverx Node...");
        
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
                LOG_INFO(Soverx::Logger::main(), "Conectando a peer {}:{}...", ip, p);
                node.connectToPeer(ip, p);
            } else {
                LOG_ERROR(Soverx::Logger::main(), "Formato de peer invalido. Use ip:port");
            }
        }

        if (config.mining_enabled) {
            LOG_INFO(Soverx::Logger::main(), "Mineria habilitada. Minando para: {}", config.miner_address);
            LOG_INFO(Soverx::Logger::main(), "Nodo corriendo.  Presione Ctrl+C para salir");
            
            // Main mining loop
            while (g_running) {
                blockchain.minePendingTransactions(config.miner_address, g_running);
                if (!g_running) break;

                // Broadcast new block
                Soverx::Block newBlock = blockchain.getLatestBlock();
                node.broadcastBlock(newBlock);
                
                std::this_thread::sleep_for(std::chrono::seconds(1)); // Throttle
            }
        } else {
            LOG_INFO(Soverx::Logger::main(), "Nodo corriendo en modo solo servidor. Presione Ctrl+C para salir");
            while (g_running) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
        
        LOG_INFO(Soverx::Logger::main(), "Guardando blockchain y cerrando...");
        blockchain.saveChain("svx_blockchain.dat");
        node.stop();
        if (rpcServer) rpcServer->stop();
    } else if (config.rpc_enabled) { // If only RPC is enabled, but not serverMode
        LOG_INFO(Soverx::Logger::main(), "RPC Server corriendo. Presione Ctrl+C para salir");
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        LOG_INFO(Soverx::Logger::main(), "Guardando blockchain y cerrando...");
        blockchain.saveChain("svx_blockchain.dat");
        if (rpcServer) rpcServer->stop();
    } else { // This case should ideally not be reached if the initial check is correct
        LOG_INFO(Soverx::Logger::main(), "Modo no especificado. Saliendo");
    }
    
    // Shutdown logger
    Soverx::Logger::shutdown();

    return 0;
}