# Radix Blockchain

<div align="center">

**A modern, custom blockchain implementation in C++ with Proof of Work consensus and peer witnessing security**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://isocpp.org/)
[![RandomX](https://img.shields.io/badge/PoW-RandomX-green.svg)](https://github.com/tevador/RandomX)

</div>

---

## 📖 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
  - [Creating a Wallet](#creating-a-wallet)
  - [Running a Node](#running-a-node)
  - [Mining](#mining)
  - [Sending Transactions](#sending-transactions)
  - [JSON-RPC API](#json-rpc-api)
- [Configuration](#configuration)
- [Network Protocol](#network-protocol)
- [Consensus Mechanism](#consensus-mechanism)
- [Development](#development)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## 🌟 Overview

**Radix** is a fully functional blockchain implementation built from scratch in C++17. It features a custom Proof of Work algorithm using RandomX, a robust P2P networking layer, UTXO-based transaction model inspired by Bitcoin, and an innovative **Peer Witnessing** consensus mechanism to prevent 51% attacks.

This project demonstrates advanced blockchain concepts including:
- UTXO (Unspent Transaction Output) management
- Digital signatures using ECDSA (secp256k1)
- Merkle tree transaction verification
- Block reorganization with security checks
- Persistent blockchain storage
- P2P network synchronization
- JSON-RPC API for external integration

---

## ✨ Features

### Core Blockchain
- ✅ **UTXO Model**: Bitcoin-style transaction handling with inputs and outputs
- ✅ **Proof of Work**: RandomX-based mining algorithm (CPU-friendly, ASIC-resistant)
- ✅ **Block Halving**: Configurable mining reward reduction (default: every 3 blocks)
- ✅ **Merkle Trees**: Efficient transaction verification
- ✅ **Persistent Storage**: Binary serialization of blockchain data
- ✅ **Chain Reorganization**: Automatic handling of forks with validation

### Security & Cryptography
- ✅ **ECDSA Signatures**: secp256k1 curve (same as Bitcoin/Ethereum)
- ✅ **SHA-256 Hashing**: For transaction and block IDs
- ✅ **Base58 Encoding**: Human-readable addresses (e.g., `radix_1A2B3C...`)
- ✅ **Peer Witnessing**: Novel consensus mechanism to detect and ban malicious nodes

### Networking
- ✅ **P2P Protocol**: Custom binary message protocol
- ✅ **Peer Discovery**: Automatic network bootstrapping
- ✅ **Block Broadcasting**: Real-time propagation of new blocks
- ✅ **Transaction Mempool**: Pending transaction management
- ✅ **Blockchain Sync**: Batch downloading from peers
- ✅ **Peer Banning**: Automatic detection and banning of malicious nodes

### User Interface
- ✅ **CLI Wallet**: Create wallets, check balances, send transactions
- ✅ **JSON-RPC Server**: HTTP API for external applications
  - `getblockcount` - Get current chain height
  - `getbalance <address>` - Query address balance
  - `sendtransaction <hex>` - Submit signed transaction
- ✅ **Mining Interface**: Built-in CPU miner with auto-broadcasting

---

## 🏗️ Architecture

```
radix_blockchain/
├── src/
│   ├── api/
│   │   ├── RpcServer.cpp/h        # JSON-RPC HTTP server
│   ├── networking/
│   │   ├── Node.cpp/h             # P2P node implementation
│   │   ├── Peer.cpp/h             # Peer connection handling
│   │   └── Message.h              # Network message protocol
│   ├── blockchain.cpp/h           # Blockchain core logic
│   ├── block.cpp/h                # Block structure and validation
│   ├── transaction.cpp/h          # Transaction handling and UTXO
│   ├── crypto.cpp/h               # ECDSA, SHA-256, Base58
│   ├── wallet.cpp/h               # Wallet key management
│   ├── randomx_util.cpp/h         # RandomX PoW wrapper
│   ├── merkle_tree.cpp/h          # Merkle tree implementation
│   ├── money_util.cpp/h           # Currency formatting (RDX)
│   ├── persistence_util.cpp/h     # Binary serialization
│   └── main.cpp                   # CLI entry point
├── tests/
│   ├── test_crypto.cpp            # Cryptography unit tests
│   ├── test_transaction.cpp       # Transaction unit tests
│   ├── test_block.cpp             # Block unit tests
│   ├── test_blockchain.cpp        # Blockchain unit tests
│   └── CMakeLists.txt             # Test build configuration
├── CMakeLists.txt                 # Build configuration
└── README.md                      # This file
```

### Key Components

#### **Blockchain** (`blockchain.cpp/h`)
- Manages the chain of blocks
- Validates and adds transactions to mempool
- Mines new blocks with Proof of Work
- Handles UTXO set for double-spend prevention
- Detects chain reorganizations (forks)

#### **Transaction** (`transaction.cpp/h`)
- UTXO-based input/output model
- Digital signatures for authorization
- Coinbase transactions for mining rewards
- Validation against UTXO set

#### **Node** (`networking/Node.cpp/h`)
- TCP socket-based P2P communication
- Handshake protocol with version negotiation
- Block and transaction broadcasting
- Blockchain synchronization from peers
- **Peer Witnessing**: Queries multiple peers to validate suspicious blocks

#### **Wallet** (`wallet.cpp/h`)
- ECDSA key pair generation (secp256k1)
- Address derivation (Base58-encoded hash160)
- Transaction creation and signing
- File-based persistence

---

## 📋 Prerequisites

### System Requirements
- **OS**: Linux, macOS, or WSL (Windows Subsystem for Linux)
- **CPU**: x86_64 with AES-NI support (for RandomX)
- **RAM**: Minimum 2GB

### Dependencies

1. **C++17 Compiler**
   ```bash
   # Ubuntu/Debian
   sudo apt install build-essential cmake
   
   # macOS
   xcode-select --install
   brew install cmake
   ```

2. **OpenSSL** (for cryptography)
   ```bash
   # Ubuntu/Debian
   sudo apt install libssl-dev
   
   # macOS
   brew install openssl@3
   ```

3. **RandomX** (Proof of Work library)
   ```bash
   git clone https://github.com/tevador/RandomX.git
   cd RandomX
   mkdir build && cd build
   cmake -DARCH=native ..
   make
   sudo make install
   ```

---

## 🛠️ Installation

### Clone the Repository
```bash
git clone https://github.com/yourusername/radix.git
cd radix
```

### Build from Source
```bash
mkdir build && cd build
cmake ..
make
```

This will create the `radix_blockchain` executable in the `build/` directory.

### Verify Installation
```bash
./radix_blockchain --help
```

### Build Docker Image (Alternative)

If you prefer to use Docker:

```bash
docker build -t radix-blockchain .
```

Or use the pre-configured multi-node setup:

```bash
docker-compose up -d
```

---

## 🚀 Usage

### Creating a Wallet

Generate a new wallet and save the private key to a file:

```bash
./radix_blockchain --new-wallet mywallet.wallet
```

**Output:**
```
✅ Nueva wallet creada en: mywallet.wallet
   Direccion: radix_1A2B3C4D5E6F7G8H9I0J
```

> ⚠️ **IMPORTANT**: Keep your wallet file secure! Anyone with access to it can spend your funds.

---

### Running a Node

#### Start a Standalone Node
```bash
./radix_blockchain --server --port 8080
```

#### Connect to an Existing Peer
```bash
./radix_blockchain --server --port 8081 --connect 127.0.0.1:8080
```

#### Enable RPC API
```bash
./radix_blockchain --server --rpc
```
- **P2P Port**: 8080 (default)
- **RPC Port**: 8090 (default)

---

### Mining

Start mining to earn block rewards:

```bash
./radix_blockchain --server --mine --miner-addr radix_1A2B3C4D5E6F7G8H9I0J
```

**Parameters:**
- `--mine`: Enable mining
- `--miner-addr <address>`: Address to receive mining rewards

**Example Output:**
```
⛏️  Minando bloque #5...
✅ Bloque minado! Hash: 000000a1b2c3d4e5f6...
💰 Recompensa: 50.00000000 RDX
```

---

### Sending Transactions

#### Check Balance
```bash
./radix_blockchain --get-balance radix_1A2B3C4D5E6F7G8H9I0J
```

**Output:**
```
💰 Balance de radix_1A2B3C4D5E6F7G8H9I0J: 150.00000000 RDX
```

#### Send RDX to Another Address
```bash
./radix_blockchain --send 1000000000 radix_RecipientAddress sender.wallet
```

**Format:**
```
--send <amount_in_rads> <recipient_address> <wallet_file>
```

> 💡 **Note**: Amount is in **rads** (1 RDX = 100,000,000 rads)

**Example:**
```bash
# Send 10 RDX
./radix_blockchain --send 1000000000 radix_9Z8Y7X6W5V4U alice.wallet
```

---

### Running with Docker

#### Quick Start (Single Node)

```bash
# Run a node with RPC enabled
docker run -d \
  -p 8080:8080 \
  -p 8090:8090 \
  -v radix-data:/radix/data \
  --name radix-node \
  radix-blockchain --server --rpc
```

#### Multi-Node Network (docker-compose)

Start 3 interconnected nodes for testing:

```bash
docker-compose up -d
```

This starts:
- **node1**: Bootstrap miner (ports 8080/8090)
- **node2**: Peer node (ports 8081/8091)
- **node3**: Peer node (ports 8082/8092)

**View logs:**
```bash
docker-compose logs -f node1
```

**Stop all nodes:**
```bash
docker-compose down
```

**Clean up (including data):**
```bash
docker-compose down -v
```

#### Custom Docker Configuration

Mount a custom config file:

```bash
docker run -d \
  -p 8080:8080 \
  -v $(pwd)/my-config.json:/radix/config.json:ro \
  -v radix-data:/radix/data \
  radix-blockchain --config config.json
```

---

### JSON-RPC API

When RPC is enabled (`--rpc`), you can interact with the blockchain via HTTP:

#### Endpoint
```
http://localhost:8090/
```

#### Available Methods

##### 1. Get Block Count
```bash
curl -X POST http://localhost:8090/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "getblockcount",
    "params": [],
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": 42,
  "id": 1
}
```

##### 2. Get Balance
```bash
curl -X POST http://localhost:8090/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "getbalance",
    "params": ["radix_1A2B3C4D5E6F7G8H9I0J"],
    "id": 2
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": "150.00000000",
  "id": 2
}
```

##### 3. Send Transaction
```bash
curl -X POST http://localhost:8090/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "sendtransaction",
    "params": ["0x48656c6c6f..."],
    "id": 3
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": "a1b2c3d4e5f6...",
  "id": 3
}
```

---

## ⚙️ Configuration

### Configuration File Support

Radix supports JSON configuration files for easier management of complex setups:

```bash
# Run with default config.json
./radix_blockchain --config config.json

# Run with custom config file
./radix_blockchain --config my-node.json
```

#### Create a Config File

Copy the example configuration:

```bash
cp config.example.json config.json
```

Edit `config.json` with your preferences:

```json
{
  "network": {
    "port": 8080,
    "connect_peer": "",
    "max_connections": 50
  },
  "mining": {
    "enabled": true,
    "miner_address": "radix_YourAddressHere",
    "threads": 4
  },
  "rpc": {
    "enabled": true,
    "port": 8090
  },
  "blockchain": {
    "data_dir": "./data",
    "difficulty": 1
  }
}
```

#### Configuration Priority

Settings are applied in this order (later overrides earlier):
1. **Defaults** (hardcoded)
2. **Config file** (`config.json` or `--config <file>`)
3. **CLI arguments** (always win)

**Example:**
```bash
# Config says port=8080, but CLI overrides to 9000
./radix_blockchain --config config.json --port 9000
```

### Configuration Options

| Section | Parameter | Type | Default | Description |
|---------|-----------|------|---------|-------------|
| `network` | `port` | int | 8080 | P2P listening port |
| | `connect_peer` | string | "" | Initial peer (ip:port) |
| | `max_connections` | int | 50 | Max peer connections |
| `mining` | `enabled` | bool | false | Enable mining |
| | `miner_address` | string | "radix_miner_default" | Mining rewards address |
| | `threads` | int | 1 | Mining threads |
| `rpc` | `enabled` | bool | false | Enable RPC server |
| | `port` | int | 8090 | RPC listening port |
| `blockchain` | `data_dir` | string | "./data" | Data directory |
| | `difficulty` | int | 1 | PoW difficulty |

### Command-Line Arguments

All config file options can be overridden via CLI:

| Argument | Description |
|----------|-------------|
| `--config <file>` | Load config from file |
| `--server` | Start in server mode |
| `--port <port>` | P2P port |
| `--connect <ip:port>` | Connect to peer |
| `--mine` | Enable mining |
| `--miner-addr <addr>` | Mining address |
| `--rpc` | Enable RPC |

> 📝 **Note**: Block halving (3 blocks) and initial reward (50 RDX) are currently hardcoded.

---

## 🌐 Network Protocol

### Message Types
- `HANDSHAKE` - Initial connection negotiation
- `NEW_BLOCK` - Broadcast newly mined block
- `NEW_TRANSACTION` - Broadcast new transaction
- `REQUEST_CHAIN` - Request blockchain synchronization
- `RESPONSE_CHAIN` - Send blockchain data
- `PEER_DISCOVERY` - Exchange known peer addresses
- `WITNESS_QUERY` - Ask peer to validate a block (anti-51% attack)
- `WITNESS_RESPONSE` - Respond to witness query

### Connection Flow
```
Node A                          Node B
  |                               |
  |-------- HANDSHAKE ----------->|
  |<------- HANDSHAKE ACK --------|
  |                               |
  |---- PEER_DISCOVERY ---------->|
  |<--- PEER_LIST ----------------|
  |                               |
  |---- REQUEST_CHAIN (height) -->|
  |<--- RESPONSE_CHAIN (blocks)---|
  |                               |
  |---- NEW_BLOCK --------------->|
  |<--- ACK ----------------------|
```

---

## 🛡️ Consensus Mechanism

### Proof of Work (RandomX)
Radix uses **RandomX**, a CPU-optimized PoW algorithm designed to resist ASIC mining:
- **Algorithm**: Random code execution in a virtual machine
- **Memory-hard**: Requires 2GB+ of fast memory
- **ASIC-resistant**: Prohibitively expensive to build dedicated hardware

### Peer Witnessing (Anti-51% Attack)
When a node suspects a malicious reorganization (deep fork), it:
1. **Pauses** acceptance of the suspicious block
2. **Queries** multiple random peers: "Do you have block X at height Y?"
3. **Validates** responses from witnesses
4. **Accepts** block if majority agrees, otherwise **bans** the suspicious peer

This prevents attackers from rewriting history, even with >51% hashrate, unless they also control the majority of network nodes.

---

## 👨‍💻 Development

### Project Status
**Current Version**: 0.1.0 (MVP)

Radix is a **serious cryptocurrency project** with the ambitious goal of becoming a competitive alternative to Bitcoin. Our vision is to create a decentralized digital currency that serves as both a **medium of exchange for payments** and a **store of value**, with the ultimate direction shaped by community adoption and use cases.

**Key Differentiators:**
- **ASIC-Resistant Mining**: RandomX ensures fair distribution through CPU mining
- **Peer Witnessing Security**: Novel consensus layer preventing 51% attacks
- **Community-Driven**: Development roadmap guided by real-world needs

**Current Implementation Status:**
- ✅ Full blockchain with UTXO model (Bitcoin-compatible architecture)
- ✅ P2P networking with synchronization
- ✅ Cryptographic security (ECDSA secp256k1, SHA-256)
- ✅ CPU-optimized mining with RandomX
- ✅ JSON-RPC API for integration
- 🚧 Production hardening in progress (Phase 2)
- 🚧 Advanced features planned (Phase 3)

While currently in MVP stage, Radix is built on solid foundations and actively progressing toward production readiness. We welcome contributors who share the vision of creating a truly decentralized, community-owned cryptocurrency.

### Building for Development
```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make
```

### Running Tests

The project includes a comprehensive test suite using **Google Test** framework with **36 unit tests** covering all core components.

#### Build and Run All Tests
```bash
cd build
cmake --build . --target radix_tests
ctest --output-on-failure
```

#### Test Coverage
- ✅ **Crypto Tests** (6/6): Key generation, signing, address derivation
- ✅ **Transaction Tests** (8/8): Coinbase, UTXO, serialization
- ✅ **Block Tests** (8/8): Mining, validation, Merkle trees
- ✅ **Blockchain Tests** (12/12): Chain management, persistence, UTXO set

#### Run Specific Test Suite
```bash
cd build
./tests/radix_tests --gtest_filter=CryptoTest.*
./tests/radix_tests --gtest_filter=TransactionTest.*
./tests/radix_tests --gtest_filter=BlockTest.*
./tests/radix_tests --gtest_filter=BlockchainTest.*
```

**Current Status**: 🟢 100% tests passing (36/36)

---

## 🗺️ Roadmap

### Phase 1: MVP Essentials (In Progress)
- [x] Core blockchain implementation
- [x] P2P networking
- [x] Wallet and transactions
- [x] Basic RPC API
- [x] Unit tests (Google Test) - 36 tests, 100% passing
- [ ] Comprehensive documentation
- [ ] Docker containerization
- [ ] Configuration file support

### Phase 2: Production Readiness
- [ ] RPC authentication (API keys)
- [ ] Rate limiting & DoS protection
- [ ] Structured logging (spdlog)
- [ ] Dynamic difficulty adjustment
- [ ] LevelDB storage backend
- [ ] Extended RPC methods
- [ ] Mempool fee prioritization

### Phase 3: Advanced Features
- [ ] HD Wallets (BIP32/44)
- [ ] Seed phrases (BIP39)
- [ ] Block explorer web UI
- [ ] Multisig transactions
- [ ] Smart contracts (basic scripting)
- [ ] Metrics dashboard (Prometheus/Grafana)

For detailed task tracking, see [task.md](/home/kabudev/.gemini/antigravity/brain/8e57e8d9-2eaf-42ba-bac9-dc4ef1922ab2/task.md).

---

## 🤝 Contributing

Contributions are welcome! Areas needing help:
- **Testing**: Write unit and integration tests
- **Documentation**: Improve code comments and guides
- **Optimization**: Performance improvements
- **Security**: Audit cryptographic implementations
- **Features**: Implement roadmap items

### Development Guidelines
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **RandomX**: [tevador/RandomX](https://github.com/tevador/RandomX) - Proof of Work algorithm
- **OpenSSL**: Cryptographic primitives
- **Bitcoin**: Inspiration for UTXO model and architecture
- **Ethereum**: Concepts for future smart contract integration

---

## 📞 Contact

For questions or discussions:
- **GitHub Issues**: [github.com/yourusername/radix/issues](https://github.com/yourusername/radix/issues)
- **Email**: your.email@example.com

---

<div align="center">

**Built with ❤️ using C++17**

</div>