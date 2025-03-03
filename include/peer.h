#ifndef PEER_H
#define PEER_H

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <memory>

#include "i2p.h"

// Forward declarations
class PeerManager;

// Peer information structure
struct PeerInfo {
    std::string username;
    std::string destination;
    uint64_t lastSeen;
};

// Peer manager class
class PeerManager {
public:
    // Singleton instance
    static PeerManager& getInstance();

    // Delete copy constructor and assignment operator
    PeerManager(const PeerManager&) = delete;
    PeerManager& operator=(const PeerManager&) = delete;

    // Initialize the peer manager
    bool initialize();

    // Lookup a peer by username
    bool lookupPeer(const std::string& username, PeerInfo& peerInfo);

    // Register a username with a destination
    bool registerUsername(const std::string& username, const std::string& destination);

    // Unregister a username
    bool unregisterUsername(const std::string& username);


    // Get the local username
    std::string getLocalUsername() const;

    // Set the local username
    void setLocalUsername(const std::string& username);

    // Get the local destination
    std::string getLocalDestination() const;

    // Set the local destination
    void setLocalDestination(const std::string& destination);

private:
    // Private constructor for singleton
    PeerManager();

    // Local peer information
    std::string localUsername;
    std::string localDestination;

    // Temporary peer cache
    std::map<std::string, PeerInfo> peerCache;

    // Mutex for thread safety
    std::mutex peerMutex;

    // I2P naming lookup
    bool lookupI2PName(const std::string& name, std::string& destination);

    // DHT lookup
    bool lookupDHT(const std::string& username, std::string& destination);

    // Custom bootstrap nodes
    std::vector<std::string> bootstrapNodes;
};

#endif // PEER_H
