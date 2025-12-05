#ifndef RADIX_MESSAGE_H
#define RADIX_MESSAGE_H

#include <cstdint>
#include <vector>
#include <string>

namespace Radix {

enum class MessageType : uint8_t {
    HANDSHAKE = 0x01,
    HANDSHAKE_ACK = 0x02,
    NEW_BLOCK = 0x03,
    NEW_TRANSACTION = 0x04,
    REQUEST_CHAIN = 0x05,
    SEND_CHAIN = 0x06,
    // Witnessing Protocol
    WITNESS_QUERY = 0x10,
    WITNESS_RESPONSE = 0x11,
    // Peer Discovery
    GET_PEERS = 0x20,
    PEER_LIST = 0x21
};

const uint32_t RADIX_NETWORK_MAGIC = 0xD9B4BEF9;


struct MessageHeader {
    uint32_t magic;      // Magic bytes to identify Radix network
    MessageType type;    // Message type
    uint32_t payloadSize;// Size of the payload
    uint32_t checksum;   // Checksum of the payload
};

struct Message {
    MessageHeader header;
    std::vector<uint8_t> payload;
};

// Payload structures
struct WitnessQueryPayload {
    uint64_t blockHeight;
    char blockHash[64 + 1]; // Null-terminated hex string
};

struct WitnessResponsePayload {
    bool agrees; // True if the peer sees the same block at that height
};

// Blockchain Synchronization Payloads
struct RequestChainPayload {
    uint64_t startHeight;   // From which height to request blocks
    uint64_t maxBlocks;     // Maximum number of blocks to send (batch size)
};

struct SendChainPayload {
    uint64_t startHeight;   // Height of first block in payload
    uint64_t blockCount;    // Number of blocks included
    // Blocks are serialized sequentially in the message payload
};

} // namespace Radix


#endif // RADIX_MESSAGE_H

