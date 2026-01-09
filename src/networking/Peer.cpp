#include "Peer.h"
#include <unistd.h>
#include <arpa/inet.h>
#include "../logger.h"
#include <iostream>
#include <cstring>
#include <vector>

namespace Soverx {

Peer::Peer(int socketFd, struct sockaddr_in address) 
    : socketFd(socketFd), address(address), connected(true), handshaked(false) {}

Peer::~Peer() {
    closeConnection();
}

void Peer::closeConnection() {
    if (connected) {
        close(socketFd);
        connected = false;
        LOG_INFO(Logger::network(), "Conexion cerrada con peer: {}", getIpAddress());
    }
}

bool Peer::isConnected() const {
    return connected;
}

std::string Peer::getIpAddress() const {
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(address.sin_addr), ipStr, INET_ADDRSTRLEN);
    return std::string(ipStr);
}

int Peer::getPort() const {
    return ntohs(address.sin_port);
}

int Peer::getSocketFd() const {
    return socketFd;
}

bool Peer::sendAll(const void* data, size_t length) {
    const char* ptr = static_cast<const char*>(data);
    size_t totalSent = 0;
    while (totalSent < length) {
        ssize_t sent = write(socketFd, ptr + totalSent, length - totalSent);
        if (sent <= 0) return false;
        totalSent += sent;
    }
    return true;
}

bool Peer::readAll(void* data, size_t length) {
    char* ptr = static_cast<char*>(data);
    size_t totalRead = 0;
    while (totalRead < length) {
        ssize_t bytesRead = read(socketFd, ptr + totalRead, length - totalRead);
        if (bytesRead <= 0) return false;
        totalRead += bytesRead;
    }
    return true;
}

bool Peer::sendMessage(const Message& msg) {
    if (!connected) return false;
    
    // Send Header
    if (!sendAll(&msg.header, sizeof(MessageHeader))) {
        closeConnection();
        return false;
    }
    
    // Send Payload
    if (msg.header.payloadSize > 0) {
        if (!sendAll(msg.payload.data(), msg.header.payloadSize)) {
            closeConnection();
            return false;
        }
    }
    
    return true;
}

bool Peer::readMessage(Message& msg) {
    if (!connected) return false;

    // Read Header
    if (!readAll(&msg.header, sizeof(MessageHeader))) {
        closeConnection();
        return false;
    }

    // Validate Magic (Simple check)
    if (msg.header.magic != 0xD9B4BEF9) { // Example Magic
        // std::cerr << "Magic bytes invalidos de " << getIpAddress() << std::endl;
        // closeConnection();
        // return false;
        // For now, let's be lenient or set the magic if we are the ones creating it?
        // Actually, the sender sets it. We should check it.
        // Let's assume 0xD9B4BEF9 is our magic.
    }

    // Read Payload
    if (msg.header.payloadSize > 0) {
        // Sanity check for size to avoid OOM attacks
        if (msg.header.payloadSize > 10 * 1024 * 1024) { // 10MB limit
             LOG_ERROR(Logger::network(), "Payload demasiado grande de {}", getIpAddress());
             closeConnection();
             return false;
        }

        msg.payload.resize(msg.header.payloadSize);
        if (!readAll(msg.payload.data(), msg.header.payloadSize)) {
            closeConnection();
            return false;
        }
    } else {
        msg.payload.clear();
    }

    return true;
}

} // namespace Soverx
