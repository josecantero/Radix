#ifndef SOVERX_PEER_H
#define SOVERX_PEER_H

#include <string>
#include <netinet/in.h>
#include "Message.h"

namespace Soverx {

class Peer {
public:
    Peer(int socketFd, struct sockaddr_in address);
    ~Peer();

    void closeConnection();
    bool isConnected() const;
    
    std::string getIpAddress() const;
    int getPort() const;
    int getSocketFd() const;

    // Send a message to this peer
    bool sendMessage(const Message& msg);
    
    // Read a message from this peer (blocking)
    bool readMessage(Message& msg);

    bool isHandshaked() const { return handshaked; }
    void setHandshaked(bool state) { handshaked = state; }

private:
    int socketFd;
    struct sockaddr_in address;
    bool connected;
    bool handshaked;
    
    bool sendAll(const void* data, size_t length);
    bool readAll(void* data, size_t length);
};

} // namespace Soverx

#endif // SOVERX_PEER_H
