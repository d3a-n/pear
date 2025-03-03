#include "../../include/chat.h"
#include "../../include/logger.h"
#include "../../include/utils.h"
#include "../../include/peer.h"
#include "../../include/serialization.h"
#include <chrono>
#include <thread>
#include <random>
#include <cstring>

// Constructor
ChatSession::ChatSession()
    : isServer(false), connected(false), running(false),
      onMessage(nullptr), onStatus(nullptr), onError(nullptr) {
    
    LOG_DEBUG("ChatSession created");
}

// Destructor
ChatSession::~ChatSession() {
    // Ensure we're disconnected
    disconnect();
    
    LOG_DEBUG("ChatSession destroyed");
}

// Initialize the chat session
bool ChatSession::initialize(const std::string& username, bool server) {
    LOG_STEP("Initializing chat session as %s", server ? "server" : "client");
    
    // Set local username
    localUsername = username;
    isServer = server;
    
    // Initialize I2P session
    if (i2p_session_init(&i2pSession, isServer) != 0) {
        notifyError("Failed to initialize I2P session");
        return false;
    }
    
    // Register username with I2P
    std::string localDest(i2pSession.local_dest.base64);
    if (!PeerManager::getInstance().registerUsername(username, localDest)) {
        notifyError("Failed to register username with I2P");
        i2p_session_close(&i2pSession);
        return false;
    }
    
    // Set local destination in peer manager
    PeerManager::getInstance().setLocalUsername(username);
    PeerManager::getInstance().setLocalDestination(localDest);
    
    notifyStatus("Chat session initialized");
    return true;
}

// Connect to a peer by username
bool ChatSession::connectToUsername(const std::string& username) {
    LOG_STEP("Connecting to peer: %s", username.c_str());
    
    // Check if already connected
    if (connected) {
        notifyError("Already connected to a peer");
        return false;
    }
    
    // Set remote username
    remoteUsername = username;
    
    // Look up the peer
    PeerInfo peerInfo;
    if (!PeerManager::getInstance().lookupPeer(username, peerInfo)) {
        notifyError("Peer not found: " + username);
        return false;
    }
    
    // Connect to the peer
    if (i2p_connect_to_username(&i2pSession, username.c_str()) != 0) {
        notifyError("Failed to connect to peer: " + username);
        return false;
    }
    
    // Send our username for connection approval
    if (i2p_session_send(&i2pSession, localUsername.c_str(), localUsername.length() + 1) != 0) {
        notifyError("Failed to send username for approval");
        i2p_session_close(&i2pSession);
        return false;
    }
    
    // Wait for acceptance/rejection response
    char response[16];
    int received = i2p_session_recv(&i2pSession, response, sizeof(response) - 1);
    if (received <= 0) {
        notifyError("Connection request timed out or rejected");
        i2p_session_close(&i2pSession);
        return false;
    }
    
    // Ensure null termination
    response[received] = '\0';
    
    // Check if rejected
    if (strcmp(response, "ACCEPTED") != 0) {
        notifyError("Connection was rejected by peer");
        i2p_session_close(&i2pSession);
        return false;
    }
    
    // Perform key exchange
    if (perform_3dh_key_exchange(i2pSession.stream_socket, 
                                localUsername.c_str(), 
                                const_cast<char*>(remoteUsername.c_str()), 
                                &sessionKeys, 
                                0) != 0) {
        notifyError("Key exchange failed");
        i2p_session_close(&i2pSession);
        return false;
    }
    
    // Set connected flag
    connected = true;
    running = true;
    
    // Start receive thread
    receiveThread = std::thread(&ChatSession::receiveLoop, this);
    
    // Start dummy traffic thread
    dummyTrafficThread = std::thread(&ChatSession::dummyTrafficLoop, this);
    
    notifyStatus("Connected to " + username);
    return true;
}

// Wait for a connection request
bool ChatSession::waitForConnectionRequest(std::string& requestUsername) {
    LOG_STEP("Waiting for connection request");
    
    // Check if already connected
    if (connected) {
        notifyError("Already connected to a peer");
        return false;
    }
    
    // Accept the incoming connection
    if (i2p_session_accept(&i2pSession) != 0) {
        notifyError("Failed to accept incoming connection");
        return false;
    }
    
    // Receive the remote username
    char remote_username[USERNAME_SIZE] = {0};
    int received = i2p_session_recv(&i2pSession, remote_username, USERNAME_SIZE - 1);
    if (received <= 0) {
        notifyError("Failed to receive username from remote peer");
        i2p_session_close(&i2pSession);
        return false;
    }
    
    // Ensure null termination
    remote_username[received] = '\0';
    
    // Store the remote username
    remoteUsername = remote_username;
    requestUsername = remoteUsername;
    
    notifyStatus("Connection request from: " + remoteUsername);
    return true;
}

// Accept or reject a connection
bool ChatSession::acceptConnection(bool accept) {
    if (!accept) {
        LOG_STEP("Rejecting connection from %s", remoteUsername.c_str());
        
        // Send rejection message
        const char* reject_msg = "REJECTED";
        i2p_session_send(&i2pSession, reject_msg, strlen(reject_msg));
        
        // Close connection
        i2p_session_close(&i2pSession);
        
        notifyStatus("Rejected connection from " + remoteUsername);
        return true;
    }
    
    LOG_STEP("Accepting connection from %s", remoteUsername.c_str());
    
    // Send acceptance message
    const char* accept_msg = "ACCEPTED";
    if (i2p_session_send(&i2pSession, accept_msg, strlen(accept_msg)) != 0) {
        notifyError("Failed to send acceptance message");
        i2p_session_close(&i2pSession);
        return false;
    }
    
    // Perform key exchange
    char remote_username[USERNAME_SIZE];
    strcpy(remote_username, remoteUsername.c_str());
    
    if (perform_3dh_key_exchange(i2pSession.stream_socket, 
                                localUsername.c_str(), 
                                remote_username, 
                                &sessionKeys, 
                                1) != 0) {
        notifyError("Key exchange failed");
        i2p_session_close(&i2pSession);
        return false;
    }
    
    // Update remote username (should be the same, but just in case)
    remoteUsername = remote_username;
    
    // Set connected flag
    connected = true;
    running = true;
    
    // Start receive thread
    receiveThread = std::thread(&ChatSession::receiveLoop, this);
    
    // Start dummy traffic thread
    dummyTrafficThread = std::thread(&ChatSession::dummyTrafficLoop, this);
    
    notifyStatus("Connected to " + remoteUsername);
    return true;
}

// Disconnect from the peer
void ChatSession::disconnect() {
    LOG_STEP("Disconnecting");
    
    // Check if connected
    if (!connected) {
        return;
    }
    
    // Stop threads
    running = false;
    
    // Send disconnect message
    serialized_message_t message;
    if (serialize_disconnect_message(&message) == 0) {
        // Encrypt the message
        unsigned char encrypted[BUFFER_SIZE];
        size_t encrypted_len = 0;
        
        if (ratchet_encrypt(&sessionKeys.ratchet, 
                           (const unsigned char*)&message.header, 
                           sizeof(message_header_t), 
                           encrypted, &encrypted_len) == 0) {
            // Send the encrypted message
            i2p_session_send(&i2pSession, encrypted, encrypted_len);
        }
        
        // Free the message
        free_serialized_message(&message);
    }
    
    // Wait for threads to finish
    if (receiveThread.joinable()) {
        receiveThread.join();
    }
    
    if (dummyTrafficThread.joinable()) {
        dummyTrafficThread.join();
    }
    
    // Close the I2P session
    i2p_session_close(&i2pSession);
    
    // Wipe session keys
    wipe_session_keys(&sessionKeys);
    
    // Reset flags
    connected = false;
    
    notifyStatus("Disconnected");
}

// Check if connected
bool ChatSession::isConnected() const {
    return connected;
}

// Send a message
bool ChatSession::sendMessage(const std::string& message) {
    LOG_DEBUG("Sending message: %s", message.c_str());
    
    // Check if connected
    if (!connected) {
        notifyError("Not connected");
        return false;
    }
    
    // Serialize the message
    serialized_message_t serialized;
    if (serialize_text_message(message.c_str(), message.length(), 
                              localUsername.c_str(), localUsername.length(), 
                              &serialized) != 0) {
        notifyError("Failed to serialize message");
        return false;
    }
    
    // Calculate total message size
    size_t total_size = sizeof(message_header_t);
    if (serialized.data) {
        total_size += serialized.data_len;
    }
    
    // Allocate buffer for the complete message
    unsigned char* buffer = new unsigned char[total_size];
    if (!buffer) {
        notifyError("Failed to allocate memory for message");
        free_serialized_message(&serialized);
        return false;
    }
    
    // Copy header
    memcpy(buffer, &serialized.header, sizeof(message_header_t));
    
    // Copy data if present
    if (serialized.data && serialized.data_len > 0) {
        memcpy(buffer + sizeof(message_header_t), serialized.data, serialized.data_len);
    }
    
    // Encrypt the message
    unsigned char encrypted[BUFFER_SIZE];
    size_t encrypted_len = 0;
    
    if (ratchet_encrypt(&sessionKeys.ratchet, buffer, total_size, 
                       encrypted, &encrypted_len) != 0) {
        notifyError("Failed to encrypt message");
        delete[] buffer;
        free_serialized_message(&serialized);
        return false;
    }
    
    // Send the encrypted message
    if (i2p_session_send(&i2pSession, encrypted, encrypted_len) != 0) {
        notifyError("Failed to send message");
        delete[] buffer;
        free_serialized_message(&serialized);
        return false;
    }
    
    // Clean up
    delete[] buffer;
    free_serialized_message(&serialized);
    
    return true;
}

// Send a ping
bool ChatSession::sendPing() {
    LOG_DEBUG("Sending ping");
    
    // Check if connected
    if (!connected) {
        notifyError("Not connected");
        return false;
    }
    
    // Serialize the ping message
    serialized_message_t message;
    if (serialize_ping_message(&message) != 0) {
        notifyError("Failed to serialize ping message");
        return false;
    }
    
    // Encrypt the message
    unsigned char encrypted[BUFFER_SIZE];
    size_t encrypted_len = 0;
    
    if (ratchet_encrypt(&sessionKeys.ratchet, 
                       (const unsigned char*)&message.header, 
                       sizeof(message_header_t), 
                       encrypted, &encrypted_len) != 0) {
        notifyError("Failed to encrypt ping message");
        free_serialized_message(&message);
        return false;
    }
    
    // Send the encrypted message
    if (i2p_session_send(&i2pSession, encrypted, encrypted_len) != 0) {
        notifyError("Failed to send ping message");
        free_serialized_message(&message);
        return false;
    }
    
    // Free the message
    free_serialized_message(&message);
    
    return true;
}

// Refresh tunnels
bool ChatSession::refreshTunnels() {
    LOG_STEP("Refreshing I2P tunnels");
    
    // Check if connected
    if (!connected) {
        notifyError("Not connected");
        return false;
    }
    
    // Refresh tunnels
    if (i2p_refresh_tunnels(&i2pSession) != 0) {
        notifyError("Failed to refresh tunnels");
        return false;
    }
    
    notifyStatus("Tunnels refreshed");
    return true;
}

// Set message callback
void ChatSession::setMessageCallback(MessageCallback callback) {
    onMessage = callback;
}

// Set status callback
void ChatSession::setStatusCallback(StatusCallback callback) {
    onStatus = callback;
}

// Set error callback
void ChatSession::setErrorCallback(ErrorCallback callback) {
    onError = callback;
}

// Get local username
std::string ChatSession::getLocalUsername() const {
    return localUsername;
}

// Get remote username
std::string ChatSession::getRemoteUsername() const {
    return remoteUsername;
}

// Get local destination
std::string ChatSession::getLocalDestination() const {
    return std::string(i2pSession.local_dest.base64);
}

// Get remote destination
std::string ChatSession::getRemoteDestination() const {
    return std::string(i2pSession.remote_dest.base64);
}

// Receive loop
void ChatSession::receiveLoop() {
    LOG_DEBUG("Receive thread started");
    
    unsigned char buffer[BUFFER_SIZE];
    
    while (running && connected) {
        // Receive data
        int received = i2p_session_recv(&i2pSession, buffer, sizeof(buffer));
        
        if (received <= 0) {
            if (running) {
                notifyError("Connection lost");
                connected = false;
            }
            break;
        }
        
        // Process the received data
        processIncomingMessage(std::vector<uint8_t>(buffer, buffer + received));
        
        // Add a small delay to prevent CPU hogging
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    LOG_DEBUG("Receive thread ended");
}

// Dummy traffic loop
void ChatSession::dummyTrafficLoop() {
    LOG_DEBUG("Dummy traffic thread started");
    
    // Random number generator
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> delay_dist(5000, 15000); // 5-15 seconds
    
    while (running && connected) {
        // Sleep for a random amount of time
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_dist(gen)));
        
        // Send dummy traffic if still connected
        if (running && connected) {
            // Create dummy message
            serialized_message_t message;
            if (serialize_dummy_message(&message) == 0) {
                // Calculate total message size
                size_t total_size = sizeof(message_header_t);
                if (message.data) {
                    total_size += message.data_len;
                }
                
                // Allocate buffer for the complete message
                unsigned char* msg_buffer = new unsigned char[total_size];
                if (msg_buffer) {
                    // Copy header
                    memcpy(msg_buffer, &message.header, sizeof(message_header_t));
                    
                    // Copy data if present
                    if (message.data && message.data_len > 0) {
                        memcpy(msg_buffer + sizeof(message_header_t), message.data, message.data_len);
                    }
                    
                    // Encrypt the message
                    unsigned char encrypted[BUFFER_SIZE];
                    size_t encrypted_len = 0;
                    
                    if (ratchet_encrypt(&sessionKeys.ratchet, msg_buffer, total_size, 
                                       encrypted, &encrypted_len) == 0) {
                        // Send the encrypted message
                        i2p_session_send(&i2pSession, encrypted, encrypted_len);
                    }
                    
                    // Clean up
                    delete[] msg_buffer;
                }
                
                // Free the message
                free_serialized_message(&message);
            }
        }
    }
    
    LOG_DEBUG("Dummy traffic thread ended");
}

// Process incoming message
void ChatSession::processIncomingMessage(const std::vector<uint8_t>& data) {
    // Decrypt the message
    unsigned char decrypted[BUFFER_SIZE];
    size_t decrypted_len = 0;
    
    if (ratchet_decrypt(&sessionKeys.ratchet, 
                       data.data(), data.size(), 
                       decrypted, &decrypted_len) != 0) {
        notifyError("Failed to decrypt message");
        return;
    }
    
    // Deserialize the message
    serialized_message_t message;
    if (deserialize_message(decrypted, decrypted_len, &message) != 0) {
        notifyError("Failed to deserialize message");
        return;
    }
    
    // Process based on message type
    switch (message.header.type) {
        case MSG_TYPE_TEXT: {
            // Extract text message
            char text[BUFFER_SIZE];
            size_t text_len = sizeof(text);
            char username[USERNAME_SIZE];
            size_t username_len = sizeof(username);
            
            if (extract_text_message(&message, text, &text_len, 
                                    username, &username_len) == 0) {
                // Null-terminate the strings
                text[text_len] = '\0';
                username[username_len] = '\0';
                
                // Create message object
                Message msg;
                msg.type = MSG_TYPE_TEXT;
                msg.sender = username;
                msg.content = text;
                msg.timestamp = message.header.timestamp;
                
                // Notify callback
                if (onMessage) {
                    onMessage(msg);
                }
            } else {
                notifyError("Failed to extract text message");
            }
            break;
        }
        
        case MSG_TYPE_PING: {
            LOG_DEBUG("Received ping, sending pong");
            
            // Send pong
            serialized_message_t pong;
            if (serialize_pong_message(&pong) == 0) {
                // Encrypt the pong
                unsigned char encrypted[BUFFER_SIZE];
                size_t encrypted_len = 0;
                
                if (ratchet_encrypt(&sessionKeys.ratchet, 
                                   (const unsigned char*)&pong.header, 
                                   sizeof(message_header_t), 
                                   encrypted, &encrypted_len) == 0) {
                    // Send the encrypted pong
                    i2p_session_send(&i2pSession, encrypted, encrypted_len);
                }
                
                // Free the pong
                free_serialized_message(&pong);
            }
            break;
        }
        
        case MSG_TYPE_PONG: {
            LOG_DEBUG("Received pong");
            
            // Create message object
            Message msg;
            msg.type = MSG_TYPE_PONG;
            msg.sender = remoteUsername;
            msg.content = "PONG";
            msg.timestamp = message.header.timestamp;
            
            // Notify callback
            if (onMessage) {
                onMessage(msg);
            }
            break;
        }
        
        case MSG_TYPE_RATCHET: {
            LOG_DEBUG("Received ratchet update");
            
            // Extract ratchet data
            unsigned char ratchet_data[BUFFER_SIZE];
            size_t ratchet_len = sizeof(ratchet_data);
            
            if (extract_ratchet_data(&message, ratchet_data, &ratchet_len) == 0) {
                // TODO: Update ratchet
                LOG_DEBUG("Ratchet update not implemented yet");
            } else {
                notifyError("Failed to extract ratchet data");
            }
            break;
        }
        
        case MSG_TYPE_DUMMY: {
            LOG_DEBUG("Received dummy traffic");
            break;
        }
        
        case MSG_TYPE_DISCONNECT: {
            LOG_DEBUG("Received disconnect message");
            
            // Notify status
            notifyStatus("Peer disconnected");
            
            // Disconnect
            connected = false;
            break;
        }
        
        default: {
            LOG_WARNING("Received unknown message type: %d", message.header.type);
            break;
        }
    }
    
    // Free the message
    free_serialized_message(&message);
}

// Send raw message
bool ChatSession::sendRawMessage(uint8_t type, const std::vector<uint8_t>& data) {
    // Check if connected
    if (!connected) {
        notifyError("Not connected");
        return false;
    }
    
    // Create message header
    message_header_t header;
    header.type = type;
    header.length = data.size();
    header.padding_len = 0;
    header.timestamp = TimeUtils::getCurrentTimeSec();
    
    // Calculate total message size
    size_t total_size = sizeof(header) + data.size();
    
    // Allocate buffer for the complete message
    unsigned char* buffer = new unsigned char[total_size];
    if (!buffer) {
        notifyError("Failed to allocate memory for message");
        return false;
    }
    
    // Copy header
    memcpy(buffer, &header, sizeof(header));
    
    // Copy data if present
    if (!data.empty()) {
        memcpy(buffer + sizeof(header), data.data(), data.size());
    }
    
    // Encrypt the message
    unsigned char encrypted[BUFFER_SIZE];
    size_t encrypted_len = 0;
    
    if (ratchet_encrypt(&sessionKeys.ratchet, buffer, total_size, 
                       encrypted, &encrypted_len) != 0) {
        notifyError("Failed to encrypt message");
        delete[] buffer;
        return false;
    }
    
    // Send the encrypted message
    if (i2p_session_send(&i2pSession, encrypted, encrypted_len) != 0) {
        notifyError("Failed to send message");
        delete[] buffer;
        return false;
    }
    
    // Clean up
    delete[] buffer;
    
    return true;
}

// Notify status
void ChatSession::notifyStatus(const std::string& status) {
    LOG_INFO("%s", status.c_str());
    if (onStatus) {
        onStatus(status);
    }
}

// Notify error
void ChatSession::notifyError(const std::string& error) {
    LOG_ERROR("%s", error.c_str());
    if (onError) {
        onError(error);
    }
}
