#!/bin/bash
# Multi-node local testing script for Radix Blockchain
# Starts 3 nodes locally for testing without Docker

set -e

echo "🚀 Starting Radix Multi-Node Test Setup"
echo "========================================"

# Check if binary exists
if [ ! -f "./build/radix_blockchain" ]; then
    echo "❌ Error: radix_blockchain not found. Run 'cd build && make' first."
    exit 1
fi

# Create local configs if they don't exist
mkdir -p configs_local

# Node 1 config (miner)
cat > configs_local/node1.json << EOF
{
  "network": {"port": 8080, "connect_peer": ""},
  "mining": {"enabled": true, "miner_address": "radix_node1_miner"},
  "rpc": {"enabled": true, "port": 8090},
  "blockchain": {"data_dir": "./data_node1", "difficulty": 1}
}
EOF

# Node 2 config (peer)
cat > configs_local/node2.json << EOF
{
  "network": {"port": 8081, "connect_peer": "127.0.0.1:8080"},
  "mining": {"enabled": false, "miner_address": "radix_node2"},
  "rpc": {"enabled": true, "port": 8091},
  "blockchain": {"data_dir": "./data_node2", "difficulty": 1}
}
EOF

# Node 3 config (peer)
cat > configs_local/node3.json << EOF
{
  "network": {"port": 8082, "connect_peer": "127.0.0.1:8080"},
  "mining": {"enabled": false, "miner_address": "radix_node3"},
  "rpc": {"enabled": true, "port": 8092},
  "blockchain": {"data_dir": "./data_node3", "difficulty": 1}
}
EOF

# Create data directories
mkdir -p data_node1 data_node2 data_node3

echo ""
echo "📡 Starting Node 1 (Bootstrap Miner) on port 8080..."
./build/radix_blockchain --config configs_local/node1.json > node1.log 2>&1 &
NODE1_PID=$!
echo "   PID: $NODE1_PID"

sleep 3

echo "📡 Starting Node 2 (Peer) on port 8081..."
./build/radix_blockchain --config configs_local/node2.json > node2.log 2>&1 &
NODE2_PID=$!
echo "   PID: $NODE2_PID"

sleep 2

echo "📡 Starting Node 3 (Peer) on port 8082..."
./build/radix_blockchain --config configs_local/node3.json > node3.log 2>&1 &
NODE3_PID=$!
echo "   PID: $NODE3_PID"

echo ""
echo "✅ All nodes started!"
echo "========================================"
echo "Node 1 (Miner):  P2P=8080, RPC=8090, PID=$NODE1_PID"
echo "Node 2 (Peer):   P2P=8081, RPC=8091, PID=$NODE2_PID"
echo "Node 3 (Peer):   P2P=8082, RPC=8092, PID=$NODE3_PID"
echo ""
echo "📝 Logs: node1.log, node2.log, node3.log"
echo ""
echo "🧪 Test RPC:"
echo "   curl -X POST http://localhost:8090/ -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"method\":\"getblockcount\",\"params\":[],\"id\":1}'"
echo ""
echo "🛑 To stop all nodes:"
echo "   kill $NODE1_PID $NODE2_PID $NODE3_PID"
echo ""
echo "Press Ctrl+C to stop all nodes..."

# Cleanup function
cleanup() {
    echo ""
    echo "🛑 Stopping all nodes..."
    kill $NODE1_PID $NODE2_PID $NODE3_PID 2>/dev/null || true
    echo "✅ All nodes stopped"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Wait for all background processes
wait
