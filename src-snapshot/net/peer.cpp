#include "../../include/peer.h"
#include "../../include/logger.h"
#include "../../include/utils.h"
#include <algorithm>
#include <fstream>
#include <sstream>
#include <ctime>

// Singleton instance
PeerManager& PeerManager::getInstance() {
    static PeerManager instance;
    return instance;
}

// Constructor
PeerManager::PeerManager() : localUsername(""), localDestination("") {
    // Constructor implementation
}

// Initialize the peer manager
bool PeerManager::initialize() {
    LOG_STEP("Initializing peer manager");
    return true;
}

// Lookup a peer by username
bool PeerManager::lookupPeer(const std::string& username, PeerInfo& peerInfo) {
    // Check if the peer is in our cache
    {
        std::lock_guard<std::mutex> lock(peerMutex);
        auto it = peerCache.find(username);
        if (it != peerCache.end()) {
            peerInfo = it->second;
            return true;
        }
    }
    
    // Try I2P naming lookup
    std::string destination;
    if (lookupI2PName(username, destination)) {
        PeerInfo peer;
        peer.username = username;
        peer.destination = destination;
        peer.lastSeen = TimeUtils::getCurrentTimeSec();
        
        std::lock_guard<std::mutex> lock(peerMutex);
        peerCache[username] = peer;
        peerInfo = peer;
        
        LOG_INFO("Found peer via I2P naming: %s", username.c_str());
        return true;
    }
    
    LOG_WARNING("Peer not found: %s", username.c_str());
    return false;
}

// Register a username with a destination
bool PeerManager::registerUsername(const std::string& username, const std::string& destination) {
    if (username.empty() || destination.empty()) {
        return false;
    }
    
    // Create I2P session
    i2p_session_t session;
    if (i2p_session_init(&session, 0) != 0) {
        LOG_ERROR("Failed to initialize I2P session for username registration");
        return false;
    }
    
    // Register the username
    if (i2p_register_username(&session, username.c_str()) != 0) {
        LOG_ERROR("Failed to register username: %s", username.c_str());
        i2p_session_close(&session);
        return false;
    }
    
    // Close the session
    i2p_session_close(&session);
    
    // Add to our cache
    PeerInfo peer;
    peer.username = username;
    peer.destination = destination;
    peer.lastSeen = TimeUtils::getCurrentTimeSec();
    
    std::lock_guard<std::mutex> lock(peerMutex);
    peerCache[username] = peer;
    
    LOG_INFO("Registered username: %s", username.c_str());
    return true;
}

// Unregister a username
bool PeerManager::unregisterUsername(const std::string& username) {
    if (username.empty()) {
        return false;
    }
    
    // Create I2P session
    i2p_session_t session;
    if (i2p_session_init(&session, 0) != 0) {
        LOG_ERROR("Failed to initialize I2P session for username unregistration");
        return false;
    }
    
    // Unregister the username
    if (i2p_unregister_username(&session, username.c_str()) != 0) {
        LOG_ERROR("Failed to unregister username: %s", username.c_str());
        i2p_session_close(&session);
        return false;
    }
    
    // Close the session
    i2p_session_close(&session);
    
    // Remove from our cache
    {
        std::lock_guard<std::mutex> lock(peerMutex);
        peerCache.erase(username);
    }
    
    LOG_INFO("Unregistered username: %s", username.c_str());
    return true;
}

// Get the local username
std::string PeerManager::getLocalUsername() const {
    return localUsername;
}

// Set the local username
void PeerManager::setLocalUsername(const std::string& username) {
    localUsername = username;
}

// Get the local destination
std::string PeerManager::getLocalDestination() const {
    return localDestination;
}

// Set the local destination
void PeerManager::setLocalDestination(const std::string& destination) {
    localDestination = destination;
}

// I2P naming lookup
bool PeerManager::lookupI2PName(const std::string& name, std::string& destination) {
    // Create I2P session
    i2p_session_t session;
    if (i2p_session_init(&session, 0) != 0) {
        LOG_ERROR("Failed to initialize I2P session for name lookup");
        return false;
    }
    
    // Look up the name
    i2p_destination_t dest;
    if (i2p_connect_to_username(&session, name.c_str()) != 0) {
        LOG_DEBUG("Name not found in I2P naming: %s", name.c_str());
        i2p_session_close(&session);
        return false;
    }
    
    // Get the destination
    destination = session.remote_dest.base64;
    
    // Close the session
    i2p_session_close(&session);
    
    return true;
}
