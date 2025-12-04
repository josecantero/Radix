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
              << "  --help            Mostrar esta ayuda\n";
}

#include <csignal>
#include <atomic>

std::atomic<bool> g_running(true);

void signalHandler(int signum) {
    std::cout << "\nInterrupcion recibida (" << signum << "). Cerrando..." << std::endl;
    g_running = false;
}

#include "wallet.h"

int main(int argc, char* argv[]) {
    initializeOpenSSL();
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    bool serverMode = false;
    int port = 8080;
    std::string connectPeer = "";
    bool mine = false;
    std::string minerAddress = "radix_miner_default"; 
    
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
            mine = true;
        } else if (strcmp(argv[i], "--miner-addr") == 0 && i + 1 < argc) {
            minerAddress = argv[++i];
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
            blockchain.addTransaction(tx);
            blockchain.saveChain("radix_blockchain.dat");
            
            // If we were connected to a network, we would broadcast here.
            // For now, since this is a CLI tool, we just save to local chain.
            // In a real scenario, we might want to connect to a node to broadcast.
            std::cout << "✅ Transaccion guardada en mempool local." << std::endl;

        } catch (const std::exception& e) {
            std::cerr << "❌ Error enviando transaccion: " << e.what() << std::endl;
            return 1;
        }
        return 0;
    }

    if (!serverMode && !mine) {
        std::cout << "Modo no especificado. Iniciando demo por defecto o usa --help.\n";
        printUsage(argv[0]);
        return 0;
    }

    std::cout << "Iniciando Radix Node..." << std::endl;
    
    Radix::Node node(blockchain);

    if (serverMode) {
        node.startServer(port);
    }

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

    std::thread miningThread;
    if (mine) {
        std::cout << "Mineria habilitada. Minando para: " << minerAddress << std::endl;
        // Mining loop in a separate thread
        miningThread = std::thread([&blockchain, &node, minerAddress]() {
            while (g_running) {
                // Check if we have transactions or just mine empty blocks?
                // For now, mine continuously
                blockchain.minePendingTransactions(minerAddress, g_running);
                
                if (!g_running) break;

                // Broadcast new block
                Radix::Block newBlock = blockchain.getLatestBlock();
                node.broadcastBlock(newBlock);
                
                std::this_thread::sleep_for(std::chrono::seconds(1)); // Throttle
            }
        });
    }

    // Keep main thread alive
    std::cout << "Nodo corriendo. Presione Ctrl+C para salir." << std::endl;
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    std::cout << "Guardando blockchain y cerrando..." << std::endl;
    blockchain.saveChain("radix_blockchain.dat");
    node.stop();
    
    if (miningThread.joinable()) {
        std::cout << "Esperando a que el hilo de mineria termine..." << std::endl;
        miningThread.join();
    }

    return 0;
}