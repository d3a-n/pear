#include "../include/common.h"
#include "../include/logger.h"
#include "../include/chat.h"
#include "../include/commands.h"
#include "../include/peer.h"
#include "../include/utils.h"
#include <iostream>
#include <string>
#include <csignal>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>

// Global variables
static std::atomic<bool> running(true);
static std::mutex inputMutex;
static std::condition_variable inputCV;
static std::string inputLine;
static bool inputReady = false;

// Forward declarations
void handleSignal(int signal);
void setupSignalHandlers();
void inputThread();
void messageCallback(const Message& message);
void statusCallback(const std::string& status);
void errorCallback(const std::string& error);
bool isValidUsername(const std::string& username);
std::string promptUsername();
bool promptServerOrClient();

int main() {
    // Initialize logger - Set to DEBUG for full verbosity
    Logger::getInstance().setLogLevel(PearLogLevel::DEBUG);
    PEAR_LOG_STEP("Pear starting up...");
    
    // Initialize random number generator
    RandomUtils::initialize();
    
    // Setup signal handlers
    setupSignalHandlers();
    
    // Register exit handlers
    register_exit_handlers();
    
#ifdef _WIN32
    // Initialize Winsock on Windows
    WSADATA wsaData;
    int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaResult != 0) {
        PEAR_LOG_ERROR("WSAStartup failed with error: %d", wsaResult);
        return EXIT_NETWORK_ERROR;
    }
    PEAR_LOG_INFO("Winsock initialized");
#endif
    
    // Initialize libsodium
    if (sodium_init() < 0) {
        PEAR_LOG_ERROR("Failed to initialize libsodium");
        return EXIT_CRYPTO_ERROR;
    }
    PEAR_LOG_INFO("Libsodium initialized");
    
    // Initialize peer manager
    if (!PeerManager::getInstance().initialize()) {
        PEAR_LOG_ERROR("Failed to initialize peer manager");
        return EXIT_FAILURE;
    }
    
    // Prompt for username
    std::string username = promptUsername();
    
    // Prompt for server or client mode
    bool isServer = promptServerOrClient();
    
    // Create chat session
    ChatSession session;
    
    // Set callbacks
    session.setMessageCallback(messageCallback);
    session.setStatusCallback(statusCallback);
    session.setErrorCallback(errorCallback);
    
    // Initialize chat session
    if (!session.initialize(username, isServer)) {
        PEAR_LOG_ERROR("Failed to initialize chat session");
        return EXIT_FAILURE;
    }
    
    // Start input thread
    std::thread input(inputThread);
    
    if (isServer) {
        PEAR_LOG_STEP("Running in server mode, waiting for connection...");
        PEAR_LOG_INFO("Your I2P destination: %s", session.getLocalDestination().c_str());
        
        // Wait for connection request
        std::string requestUsername;
        if (!session.waitForConnectionRequest(requestUsername)) {
            PEAR_LOG_ERROR("Failed to receive connection request");
            running = false;
            inputCV.notify_all();
            input.join();
            return EXIT_NETWORK_ERROR;
        }
        
        // Prompt to accept connection
        std::string response;
        std::cout << "Accept connection from " << requestUsername << "? (y/n): ";
        std::getline(std::cin, response);
        
        bool accept = false;
        if (!response.empty() && (response[0] == 'y' || response[0] == 'Y')) {
            accept = true;
        }
        
        // Accept or reject the connection
        if (!session.acceptConnection(accept)) {
            if (accept) {
                PEAR_LOG_ERROR("Failed to accept connection");
                running = false;
                inputCV.notify_all();
                input.join();
                return EXIT_NETWORK_ERROR;
            } else {
                PEAR_LOG_INFO("Connection rejected");
                return EXIT_SUCCESS;
            }
        }
        
        if (accept) {
            PEAR_LOG_INFO("Connected to %s", session.getRemoteUsername().c_str());
        } else {
            PEAR_LOG_INFO("Connection rejected");
            running = false;
            inputCV.notify_all();
            input.join();
            return EXIT_SUCCESS;
        }
    } else {
        PEAR_LOG_STEP("Running in client mode");
        PEAR_LOG_INFO("Your I2P destination: %s", session.getLocalDestination().c_str());
        
        // Prompt for peer username
        std::string peerUsername;
        std::cout << "Enter peer username: ";
        std::getline(std::cin, peerUsername);
        
        PEAR_LOG_STEP("Connecting to %s...", peerUsername.c_str());
        
        // Connect to peer
        if (!session.connectToUsername(peerUsername)) {
            PEAR_LOG_ERROR("Failed to connect to %s", peerUsername.c_str());
            running = false;
            inputCV.notify_all();
            input.join();
            return EXIT_NETWORK_ERROR;
        }
        
        PEAR_LOG_INFO("Connected to %s", session.getRemoteUsername().c_str());
    }
    
    // Main loop
    while (running) {
        // Wait for input
        {
            std::unique_lock<std::mutex> lock(inputMutex);
            inputCV.wait(lock, []{ return inputReady || !running; });
            
            if (!running) {
                break;
            }
            
            // Process input
            if (inputReady) {
                std::string line = inputLine;
                inputReady = false;
                
                // Check if it's a command
                if (isCommand(line)) {
                    CommandProcessor::getInstance().processCommand(line, &session);
                } else {
                    // Send as message
                    session.sendMessage(line);
                }
            }
        }
    }
    
    // Disconnect
    session.disconnect();
    
    // Wait for input thread to finish
    inputCV.notify_all();
    if (input.joinable()) {
        input.join();
    }
    
#ifdef _WIN32
    // Cleanup Winsock on Windows
    WSACleanup();
#endif
    
    PEAR_LOG_STEP("Pear shutting down...");
    return EXIT_SUCCESS;
}

// Signal handler
void handleSignal(int signal) {
    PEAR_LOG_INFO("Received signal %d", signal);
    running = false;
    inputCV.notify_all();
}

// Setup signal handlers
void setupSignalHandlers() {
    signal(SIGINT, handleSignal);
    signal(SIGTERM, handleSignal);
#ifndef _WIN32
    signal(SIGQUIT, handleSignal);
    signal(SIGHUP, handleSignal);
#endif
}

// Input thread
void inputThread() {
    while (running) {
        std::string line;
        std::getline(std::cin, line);
        
        if (!running) {
            break;
        }
        
        {
            std::lock_guard<std::mutex> lock(inputMutex);
            inputLine = line;
            inputReady = true;
        }
        
        inputCV.notify_one();
    }
}

// Message callback
void messageCallback(const Message& message) {
    // Print the message
    switch (message.type) {
        case MSG_TYPE_TEXT:
            std::cout << "[" << message.sender << "] " << message.content << std::endl;
            break;
            
        case MSG_TYPE_PING:
            std::cout << "[PING] from " << message.sender << std::endl;
            break;
            
        case MSG_TYPE_PONG:
            std::cout << "[PONG] from " << message.sender << std::endl;
            break;
            
        default:
            // Ignore other message types
            break;
    }
}

// Status callback
void statusCallback(const std::string& status) {
    std::cout << "[STATUS] " << status << std::endl;
}

// Error callback
void errorCallback(const std::string& error) {
    std::cerr << "[ERROR] " << error << std::endl;
}

// Check if username is valid
bool isValidUsername(const std::string& username) {
    if (username.empty() || username.length() > USERNAME_SIZE - 1) {
        return false;
    }
    
    for (char c : username) {
        if (!std::isalnum(c) && c != '_') {
            return false;
        }
    }
    
    return true;
}

// Prompt for username
std::string promptUsername() {
    std::string username;
    
    while (true) {
        std::cout << "Enter your username (alphanumeric or underscores): ";
        std::getline(std::cin, username);
        
        if (isValidUsername(username)) {
            break;
        }
        
        std::cout << "Invalid username. Use letters, digits, or underscores." << std::endl;
    }
    
    return username;
}

// Prompt for server or client mode
bool promptServerOrClient() {
    std::string choice;
    
    while (true) {
        std::cout << "Press 'c' to connect as client, or ENTER to run as server: ";
        std::getline(std::cin, choice);
        
        if (choice.empty() || (choice.length() == 1 && std::tolower(choice[0]) == 'c')) {
            break;
        }
        
        std::cout << "Invalid input. Press 'c' (client) or ENTER (server)." << std::endl;
    }
    
    return choice.empty();
}
