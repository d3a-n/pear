#include <string>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <boost/asio.hpp>

// i2pd headers
#include "api.h"
#include "ClientContext.h"
#include "SAM.h"

// Our headers
#include "../../include/i2p.h"
#include "../../include/common.h"
#include "../../include/logger.h"

// Global variables
static std::shared_ptr<std::thread> g_I2PThread = nullptr;
static std::mutex g_I2PMutex;
static std::condition_variable g_I2PCondVar;
static bool g_I2PRunning = false;
static bool g_I2PInitialized = false;

// SAM bridge
static i2p::client::SAMBridge* g_SAMBridge = nullptr;

extern "C" {

// Initialize and start i2pd
int i2pd_start(void) {
    std::lock_guard<std::mutex> lock(g_I2PMutex);
    
    if (g_I2PRunning) {
        LOG_INFO("I2PD is already running");
        return 0; // Already running
    }
    
    if (!g_I2PInitialized) {
        LOG_STEP("Initializing I2PD...");
        
        try {
            // Initialize i2pd with default options
            char* argv[] = { (char*)"i2pd", nullptr };
            i2p::api::InitI2P(1, argv, "pear");
            g_I2PInitialized = true;
            
            // Start i2pd directly
            LOG_INFO("Starting I2PD core...");
            i2p::api::StartI2P();
            
            // Run i2pd
            i2p::client::context.Start();
            
            // Create SAM bridge on localhost:7656
            g_SAMBridge = new i2p::client::SAMBridge("127.0.0.1", 7656, 7656, true);
            g_SAMBridge->Start();
            
            g_I2PRunning = true;
            LOG_INFO("I2PD core started successfully");
            
            return 0;
        }
        catch (const std::exception& ex) {
            LOG_ERROR("Failed to initialize I2PD: %s", ex.what());
            return -1;
        }
    }
    
    return 0;
}

// Stop i2pd
int i2pd_stop(void) {
    std::lock_guard<std::mutex> lock(g_I2PMutex);
    
    if (!g_I2PRunning) {
        return 0; // Not running
    }
    
    try {
        LOG_STEP("Stopping I2PD...");
        
        // Stop SAM bridge
        if (g_SAMBridge) {
            g_SAMBridge->Stop();
            delete g_SAMBridge;
            g_SAMBridge = nullptr;
        }
        
        // Stop i2pd
        i2p::client::context.Stop();
        i2p::api::StopI2P();
        
        // Wait for the thread to finish
        if (g_I2PThread && g_I2PThread->joinable()) {
            g_I2PThread->join();
            g_I2PThread = nullptr;
        }
        
        g_I2PRunning = false;
        LOG_INFO("I2PD stopped successfully");
        
        return 0;
    }
    catch (const std::exception& ex) {
        LOG_ERROR("Failed to stop I2PD: %s", ex.what());
        return -1;
    }
}

// Check if i2pd is running
int i2pd_is_running(void) {
    std::lock_guard<std::mutex> lock(g_I2PMutex);
    return g_I2PRunning ? 1 : 0;
}

// Connect to SAM bridge
int sam_connect(const char *sam_host, int sam_port) {
    if (!sam_host) {
        return -1;
    }
    
    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }
    
    // Set up server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(sam_port);
    
    // Convert hostname to IP address
    struct hostent *he = gethostbyname(sam_host);
    if (!he) {
        socket_close(sock);
        return -1;
    }
    
    memcpy(&server_addr.sin_addr, he->h_addr_list[0], he->h_length);
    
    // Connect to SAM bridge
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        socket_close(sock);
        return -1;
    }
    
    return sock;
}

// Disconnect from SAM bridge
int sam_disconnect(int sam_socket) {
    if (sam_socket < 0) {
        return -1;
    }
    
    socket_close(sam_socket);
    return 0;
}

// Send HELLO message to SAM bridge
int sam_hello(int sam_socket) {
    if (sam_socket < 0) {
        return -1;
    }
    
    // Send HELLO message
    const char *hello_msg = "HELLO VERSION MIN=3.0 MAX=3.3\n";
    if (send_all(sam_socket, hello_msg, strlen(hello_msg), 0) < 0) {
        return -1;
    }
    
    // Receive response
    char buffer[BUFFER_SIZE];
    ssize_t received = recv(sam_socket, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) {
        return -1;
    }
    
    // Null-terminate the response
    buffer[received] = '\0';
    
    // Check if the response is OK
    if (strstr(buffer, "HELLO REPLY RESULT=OK") == NULL) {
        return -1;
    }
    
    return 0;
}

// Generate a new destination
int sam_generate_destination(int sam_socket, i2p_destination_t *dest) {
    if (sam_socket < 0 || !dest) {
        return -1;
    }
    
    // Send DEST GENERATE message
    const char *gen_msg = "DEST GENERATE\n";
    if (send_all(sam_socket, gen_msg, strlen(gen_msg), 0) < 0) {
        return -1;
    }
    
    // Receive response
    char buffer[BUFFER_SIZE];
    ssize_t received = recv(sam_socket, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) {
        return -1;
    }
    
    // Null-terminate the response
    buffer[received] = '\0';
    
    // Check if the response is OK
    char *priv_begin = strstr(buffer, "DEST REPLY PUB=");
    if (!priv_begin) {
        return -1;
    }
    
    // Extract the destination
    priv_begin += 14; // Skip "DEST REPLY PUB="
    char *priv_end = strstr(priv_begin, " PRIV=");
    if (!priv_end) {
        return -1;
    }
    
    // Copy the destination
    size_t dest_len = priv_end - priv_begin;
    if (dest_len >= I2P_DEST_SIZE) {
        return -1;
    }
    
    memcpy(dest->base64, priv_begin, dest_len);
    dest->base64[dest_len] = '\0';
    dest->len = dest_len;
    
    return 0;
}

// Create a SAM session
int sam_create_session(int sam_socket, const char *session_id, const i2p_destination_t *dest) {
    if (sam_socket < 0 || !session_id || !dest) {
        return -1;
    }
    
    // Send SESSION CREATE message
    char create_msg[BUFFER_SIZE];
    snprintf(create_msg, sizeof(create_msg),
             "SESSION CREATE STYLE=STREAM ID=%s DESTINATION=%s\n",
             session_id, dest->base64);
    
    if (send_all(sam_socket, create_msg, strlen(create_msg), 0) < 0) {
        return -1;
    }
    
    // Receive response
    char buffer[BUFFER_SIZE];
    ssize_t received = recv(sam_socket, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) {
        return -1;
    }
    
    // Null-terminate the response
    buffer[received] = '\0';
    
    // Check if the response is OK
    if (strstr(buffer, "SESSION STATUS RESULT=OK") == NULL) {
        return -1;
    }
    
    return 0;
}

// Lookup a name in the SAM bridge
int sam_lookup_name(int sam_socket, const char *name, i2p_destination_t *dest) {
    if (sam_socket < 0 || !name || !dest) {
        return -1;
    }
    
    // Send NAMING LOOKUP message
    char lookup_msg[BUFFER_SIZE];
    snprintf(lookup_msg, sizeof(lookup_msg), "NAMING LOOKUP NAME=%s\n", name);
    
    if (send_all(sam_socket, lookup_msg, strlen(lookup_msg), 0) < 0) {
        return -1;
    }
    
    // Receive response
    char buffer[BUFFER_SIZE];
    ssize_t received = recv(sam_socket, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) {
        return -1;
    }
    
    // Null-terminate the response
    buffer[received] = '\0';
    
    // Check if the response is OK
    char *value_begin = strstr(buffer, "NAMING REPLY RESULT=OK VALUE=");
    if (!value_begin) {
        return -1;
    }
    
    // Extract the destination
    value_begin += 28; // Skip "NAMING REPLY RESULT=OK VALUE="
    char *value_end = strstr(value_begin, "\n");
    if (!value_end) {
        value_end = buffer + received;
    }
    
    // Copy the destination
    size_t dest_len = value_end - value_begin;
    if (dest_len >= I2P_DEST_SIZE) {
        return -1;
    }
    
    memcpy(dest->base64, value_begin, dest_len);
    dest->base64[dest_len] = '\0';
    dest->len = dest_len;
    
    return 0;
}

// Alias for sam_lookup_name
int sam_name_lookup(int sam_socket, const char *name, i2p_destination_t *dest) {
    return sam_lookup_name(sam_socket, name, dest);
}

} // extern "C"
