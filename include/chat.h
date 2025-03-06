#ifndef CHAT_H
#define CHAT_H

#include <string>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <thread>
#include <functional>

#include "i2p.h"
#include "crypto.h"

// Forward declarations
class ChatSession;

// Message structure
struct Message {
    uint8_t type;                // Message type
    std::string sender;          // Sender username
    std::string content;         // Message content
    std::vector<uint8_t> data;   // Raw message data
    uint64_t timestamp;          // Message timestamp
};

// Chat session callback types
using MessageCallback = std::function<void(const Message&)>;
using StatusCallback = std::function<void(const std::string&)>;
using ErrorCallback = std::function<void(const std::string&)>;

// Chat session class
class ChatSession {
public:
    // Constructor/destructor
    ChatSession();
    ~ChatSession();

    // Delete copy constructor and assignment operator
    ChatSession(const ChatSession&) = delete;
    ChatSession& operator=(const ChatSession&) = delete;

    // Session initialization
    bool initialize(const std::string& username, bool isServer);
    
    // Connection management
    bool connectToUsername(const std::string& username);
    bool waitForConnectionRequest(std::string& remoteUsername);
    bool acceptConnection(bool accept);
    void disconnect();
    bool isConnected() const;
    
    // Message sending
    bool sendMessage(const std::string& message);
    bool sendPing();
    
    // Tunnel management
    bool refreshTunnels();
    
    // Callback registration
    void setMessageCallback(MessageCallback callback);
    void setStatusCallback(StatusCallback callback);
    void setErrorCallback(ErrorCallback callback);
    
    // Username getters
    std::string getLocalUsername() const;
    std::string getRemoteUsername() const;
    
    // I2P destination getters
    std::string getLocalDestination() const;
    std::string getRemoteDestination() const;

private:
    // Session data
    std::string localUsername;
    std::string remoteUsername;
    i2p_session_t i2pSession;
    session_keys_t sessionKeys;
    bool isServer;
    std::atomic<bool> connected;
    std::atomic<bool> running;
    
    // Callbacks
    MessageCallback onMessage;
    StatusCallback onStatus;
    ErrorCallback onError;
    
    // Threads
    std::thread receiveThread;
    // dummyTrafficThread removed
    
    // Thread synchronization
    std::mutex sessionMutex;
    std::condition_variable sessionCondVar;
    
    // Private methods
    void receiveLoop();
    // dummyTrafficLoop method removed
    void processIncomingMessage(const std::vector<uint8_t>& data);
    bool sendRawMessage(uint8_t type, const std::vector<uint8_t>& data);
    void notifyStatus(const std::string& status);
    void notifyError(const std::string& error);
};

#endif // CHAT_H
