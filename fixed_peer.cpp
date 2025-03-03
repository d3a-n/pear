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
    // Initialize bootstrap nodes
    bootstrapNodes = {
        "pear-bootstrap.i2p",
        "pear-node1.i2p",
        "pear-node2.i2p"
    };
}

// Initialize the peer manager
bool PeerManager::initialize() {
    LOG_STEP("Initializing peer manager");
    
    // Load trusted peers from file
    std::string configDir = SystemUtils::getHomeDirectory() + PATH_SEPARATOR + ".pear";
    
    // Create config directory if it doesn't exist
    if (!SystemUtils::createDirectory(configDir)) {
        LOG_ERROR("Failed to create config directory: %s", configDir.c_str());
        return false;
    }
    
    std::string peersFile = configDir + PATH_SEPARATOR + "trusted_peers.txt";
    
    if (SystemUtils::fileExists(peersFile)) {
        std::ifstream file(peersFile);
        if (file.is_open()) {
            std::string line;
            while (std::getline(file, line)) {
                line = StringUtils::trim(line);
                if (line.empty() || line[0] == '#') {
                    continue; // Skip empty lines and comments
                }
                
                std::vector<std::string> parts = StringUtils::split(line, '|');
                if (parts.size() >= 2) {
                    PeerInfo peer;
                    peer.username = StringUtils::trim(parts[0]);
                    peer.destination = StringUtils::trim(parts[1]);
                    peer.lastSeen = (parts.size() >= 3) ? std::stoull(parts[2]) : 0;
                    peer.trusted = true;
                    
                    std::lock_guard<std::mutex> lock(peerMutex);
                    peers[peer.username] = peer;
                    
                    LOG_DEBUG("Loaded trusted peer: %s", peer.username.c_str());
                }
            }
            file.close();
        } else {
            LOG_WARNING("Could not open trusted peers file: %s", peersFile.c_str());
        }
    } else {
        LOG_INFO("No trusted peers file found, will create one when peers are added");
    }
    
    return true;
}

// Lookup a peer by username
bool PeerManager::lookupPeer(const std::string& username, PeerInfo& peerInfo) {
    // Check if the peer is in our database
    {
        std::lock_guard<std::mutex> lock(peerMutex);
        auto it = peers.find(username);
        if (it != peers.end()) {
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
        peer.trusted = false;
        
        std::lock_guard<std::mutex> lock(peerMutex);
        peers[username] = peer;
        peerInfo = peer;
        
        LOG_INFO("Found peer via I2P naming: %s", username.c_str());
        return true;
    }
    
    // Try DHT lookup
    if (lookupDHT(username, destination)) {
        PeerInfo peer;
        peer.username = username;
        peer.destination = destination;
        peer.lastSeen = TimeUtils::getCurrentTimeSec();
        peer.trusted = false;
        
        std::lock_guard<std::mutex> lock(peerMutex);
        peers[username] = peer;
        peerInfo = peer;
        
        LOG_INFO("Found peer via DHT: %s", username.c_str());
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
    
    // Add to our database
    PeerInfo peer;
    peer.username = username;
    peer.destination = destination;
    peer.lastSeen = TimeUtils::getCurrentTimeSec();
    peer.trusted = true;
    
    std::lock_guard<std::mutex> lock(peerMutex);
    peers[username] = peer;
    
    // Save to trusted peers file
    saveTrustedPeers();
    
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
    
    // Remove from our database
    {
        std::lock_guard<std::mutex> lock(peerMutex);
        peers.erase(username);
    }
    
    // Save to trusted peers file
    saveTrustedPeers();
    
    LOG_INFO("Unregistered username: %s", username.c_str());
    return true;
}

// Add a trusted peer
void PeerManager::addTrustedPeer(const std::string& username, const std::string& destination) {
    if (username.empty() || destination.empty()) {
        return;
    }
    
    PeerInfo peer;
    peer.username = username;
    peer.destination = destination;
    peer.lastSeen = TimeUtils::getCurrentTimeSec();
    peer.trusted = true;
    
    std::lock_guard<std::mutex> lock(peerMutex);
    peers[username] = peer;
    
    // Save to trusted peers file
    saveTrustedPeers();
    
    LOG_INFO("Added trusted peer: %s", username.c_str());
}

// Remove a trusted peer
void PeerManager::removeTrustedPeer(const std::string& username) {
    std::lock_guard<std::mutex> lock(peerMutex);
    
    auto it = peers.find(username);
    if (it != peers.end()) {
        if (it->second.trusted) {
            it->second.trusted = false;
            
            // Save to trusted peers file
            saveTrustedPeers();
            
            LOG_INFO("Removed trusted peer: %s", username.c_str());
        }
    }
}

// Get all trusted peers
std::vector<PeerInfo> PeerManager::getTrustedPeers() {
    std::vector<PeerInfo> trustedPeers;
    
    std::lock_guard<std::mutex> lock(peerMutex);
    for (const auto& pair : peers) {
        if (pair.second.trusted) {
            trustedPeers.push_back(pair.second);
        }
    }
    
    return trustedPeers;
}

// Check if a peer is trusted
bool PeerManager::isPeerTrusted(const std::string& username) {
    std::lock_guard<std::mutex> lock(peerMutex);
    
    auto it = peers.find(username);
    if (it != peers.end()) {
        return it->second.trusted;
    }
    
    return false;
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

// DHT lookup
bool PeerManager::lookupDHT(const std::string& username, std::string& destination) {
    // This is a placeholder for DHT lookup
    // In a real implementation, we would use a DHT library to look up the username
    
    // For now, we'll just return false
    return false;
}

// Save trusted peers to file
void PeerManager::saveTrustedPeers() {
    std::string configDir = SystemUtils::getHomeDirectory() + PATH_SEPARATOR + ".pear";
    std::string peersFile = configDir + PATH_SEPARATOR + "trusted_peers.txt";
    
    std::ofstream file(peersFile);
    if (file.is_open()) {
        file << "# Pear trusted peers file" << std::endl;
        file << "# Format: username|destination|last_seen_timestamp" << std::endl;
        file << std::endl;
        
        for (const auto& pair : peers) {
            if (pair.second.trusted) {
                file << pair.second.username << "|"
                     << pair.second.destination << "|"
                     << pair.second.lastSeen << std::endl;
            }
        }
        
        file.close();
        LOG_DEBUG("Saved trusted peers to file: %s", peersFile.c_str());
    } else {
        LOG_ERROR("Could not open trusted peers file for writing: %s", peersFile.c_str());
    }
}
