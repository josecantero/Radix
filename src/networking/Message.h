#ifndef SOVERX_MESSAGE_H
#define SOVERX_MESSAGE_H

#include <cstdint>
#include <vector>
#include <string>
#include <cstring> // For memcpy
#include <zlib.h>  // For crc32

namespace Soverx {

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

const uint32_t SOVERX_NETWORK_MAGIC = 0xD9B4BEF9; // Updated magic

struct MessageHeader {
    uint32_t magic;      // Magic bytes to identify Soverx network
    MessageType type;    // Message type
    uint32_t payloadSize;// Size of the payload
    uint32_t checksum;   // Checksum of the payload
};

struct Message {
    MessageHeader header;
    std::vector<uint8_t> payload;
};

// Payload structures

struct RequestChainPayload {
    uint64_t startHeight;
    uint64_t maxBlocks;
};

struct WitnessQueryPayload {
    uint64_t blockHeight;
    char blockHash[65]; // 64 chars + null terminator
};

struct WitnessResponsePayload {
    bool agrees;
    char blockHash[65]; // Optional: to confirm which block
};

// Checksum function (CRC32)
inline uint32_t calculateChecksum(const std::vector<uint8_t>& data) {
    if (data.empty()) return 0;
    return crc32(0L, data.data(), data.size());
}

inline bool validateChecksum(const Message& msg) {
    return msg.header.checksum == calculateChecksum(msg.payload);
}

} // namespace Soverx

#endif // SOVERX_MESSAGE_H
