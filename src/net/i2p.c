#include "../../include/i2p.h"
#include "../../include/common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#endif

// If I2P support is disabled (for Windows cross-compilation), provide stub implementations
#ifndef DISABLE_I2P

/* I2PD process handle */
#ifdef _WIN32
static HANDLE i2pd_process = NULL;
static DWORD i2pd_pid = 0;
#else
static pid_t i2pd_pid = -1;
#endif

#else // DISABLE_I2P is defined

// Stub declarations for when I2P is disabled
#ifdef _WIN32
static HANDLE i2pd_process = NULL;
static DWORD i2pd_pid = 0;
#else
static pid_t i2pd_pid = -1;
#endif

#endif // DISABLE_I2P

/* SAM API port */
static int sam_port = 7656;

/* I2P daemon control */
int i2pd_start(void) {
#ifndef DISABLE_I2P
    // Check if I2PD is already running
    if (i2pd_is_running()) {
        return 0; // Already running
    }

#ifdef _WIN32
    // Windows implementation
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    
    // Hide the console window
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    // Command line for I2PD with SAM enabled
    char cmdline[] = "i2pd.exe --sam.enabled true --sam.port 7656";
    
    // Create the process
    if (!CreateProcess(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        return -1;
    }
    
    // Save the process handle and ID
    i2pd_process = pi.hProcess;
    i2pd_pid = pi.dwProcessId;
    
    // Close the thread handle
    CloseHandle(pi.hThread);
    
    // Wait for I2PD to start
    Sleep(2000); // 2 seconds
    
    // Check if I2PD is running
    if (!i2pd_is_running()) {
        CloseHandle(i2pd_process);
        i2pd_process = NULL;
        i2pd_pid = 0;
        return -1;
    }
    
    return 0;
#else
    // Unix implementation
    i2pd_pid = fork();
    
    if (i2pd_pid < 0) {
        // Fork failed
        return -1;
    } else if (i2pd_pid == 0) {
        // Child process - execute I2PD
        
        // Redirect stdout and stderr to /dev/null
        int null_fd = open("/dev/null", O_WRONLY);
        if (null_fd >= 0) {
            dup2(null_fd, STDOUT_FILENO);
            dup2(null_fd, STDERR_FILENO);
            close(null_fd);
        }
        
        // Execute I2PD with SAM enabled
        execlp("i2pd", "i2pd", "--sam.enabled", "true", "--sam.port", "7656", NULL);
        
        // If execlp returns, it failed
        exit(EXIT_FAILURE);
    }
    
    // Parent process - wait for I2PD to start
    sleep(2); // Give I2PD time to start
    
    // Check if I2PD is running
    if (!i2pd_is_running()) {
        return -1;
    }
    
    return 0;
#endif
}
#else // DISABLE_I2P is defined
    // Stub implementation when I2P is disabled
    return -1;
}
#endif // DISABLE_I2P

int i2pd_stop(void) {
#ifndef DISABLE_I2P
    // Check if I2PD is running
    if (!i2pd_is_running()) {
        return 0; // Not running
    }
    
#ifdef _WIN32
    // Windows implementation
    if (TerminateProcess(i2pd_process, 0)) {
        // Wait for the process to exit
        WaitForSingleObject(i2pd_process, 5000); // Wait up to 5 seconds
        
        // Close the process handle
        CloseHandle(i2pd_process);
        i2pd_process = NULL;
        i2pd_pid = 0;
        
        return 0;
    }
    
    return -1;
#else
    // Unix implementation
    // Send SIGTERM to I2PD
    if (kill(i2pd_pid, SIGTERM) < 0) {
        return -1;
    }
    
    // Wait for I2PD to exit
    int status;
    if (waitpid(i2pd_pid, &status, 0) < 0) {
        return -1;
    }
    
    i2pd_pid = -1;
    return 0;
#endif
}
#else // DISABLE_I2P is defined
    // Stub implementation when I2P is disabled
    return -1;
}
#endif // DISABLE_I2P

int i2pd_is_running(void) {
#ifndef DISABLE_I2P
#ifdef _WIN32
    // Windows implementation
    if (i2pd_process == NULL || i2pd_pid == 0) {
        return 0; // Not running
    }
    
    // Check if process is still running
    DWORD exit_code;
    if (!GetExitCodeProcess(i2pd_process, &exit_code)) {
        // Error getting exit code
        CloseHandle(i2pd_process);
        i2pd_process = NULL;
        i2pd_pid = 0;
        return 0;
    }
    
    if (exit_code != STILL_ACTIVE) {
        // Process has exited
        CloseHandle(i2pd_process);
        i2pd_process = NULL;
        i2pd_pid = 0;
        return 0;
    }
    
    // Process is still running
    return 1;
#else
    // Unix implementation
    if (i2pd_pid <= 0) {
        return 0; // Not running
    }
    
    // Check if process exists
    if (kill(i2pd_pid, 0) < 0) {
        if (errno == ESRCH) {
            // Process does not exist
            i2pd_pid = -1;
            return 0;
        }
    }
    
    // Process exists
    return 1;
#endif
}
#else // DISABLE_I2P is defined
    // Stub implementation when I2P is disabled
    return 0;
}
#endif // DISABLE_I2P

/* SAM API functions */
int sam_connect(const char *sam_host, int sam_port) {
#ifndef DISABLE_I2P
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
#else // DISABLE_I2P is defined
    // Stub implementation when I2P is disabled
    (void)sam_host;
    (void)sam_port;
    return -1;
}
#endif // DISABLE_I2P

int sam_disconnect(int sam_socket) {
#ifndef DISABLE_I2P
    if (sam_socket < 0) {
        return -1;
    }
    
    socket_close(sam_socket);
    return 0;
}
#else // DISABLE_I2P is defined
    // Stub implementation when I2P is disabled
    (void)sam_socket;
    return -1;
}
#endif // DISABLE_I2P

int sam_hello(int sam_socket) {
#ifndef DISABLE_I2P
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
#else // DISABLE_I2P is defined
    // Stub implementation when I2P is disabled
    (void)sam_socket;
    return -1;
}
#endif // DISABLE_I2P

int sam_generate_destination(int sam_socket, i2p_destination_t *dest) {
#ifndef DISABLE_I2P
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
#else // DISABLE_I2P is defined
    // Stub implementation when I2P is disabled
    (void)sam_socket;
    (void)dest;
    return -1;
}
#endif // DISABLE_I2P

int sam_create_session(int sam_socket, const char *session_id, const i2p_destination_t *dest) {
#ifndef DISABLE_I2P
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
#else // DISABLE_I2P is defined
    // Stub implementation when I2P is disabled
    (void)sam_socket;
    (void)session_id;
    (void)dest;
    return -1;
}
#endif // DISABLE_I2P

int sam_lookup_name(int sam_socket, const char *name, i2p_destination_t *dest) {
#ifndef DISABLE_I2P
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
#else // DISABLE_I2P is defined
    // Stub implementation when I2P is disabled
    (void)sam_socket;
    (void)name;
    (void)dest;
    return -1;
}
#endif // DISABLE_I2P

int sam_name_lookup(int sam_socket, const char *name, i2p_destination_t *dest) {
    return sam_lookup_name(sam_socket, name, dest);
}

/* I2P session management */
int i2p_session_init(i2p_session_t *session, int is_server) {
#ifndef DISABLE_I2P
    if (!session) {
        return -1;
    }
    
    // Initialize the session
    memset(session, 0, sizeof(i2p_session_t));
    session->is_server = is_server;
    session->sam_socket = -1;
    session->stream_socket = -1;
    
    // Initialize the mutex
    if (pthread_mutex_init(&session->mutex, NULL) != 0) {
        return -1;
    }
    
    // Start I2PD if not running
    if (!i2pd_is_running()) {
        if (i2pd_start() != 0) {
            return -1;
        }
    }
    
    // Connect to SAM bridge
    session->sam_socket = sam_connect("127.0.0.1", sam_port);
    if (session->sam_socket < 0) {
        return -1;
    }
    
    // Send HELLO message
    if (sam_hello(session->sam_socket) != 0) {
        sam_disconnect(session->sam_socket);
        session->sam_socket = -1;
        return -1;
    }
    
    // Generate a destination
    if (sam_generate_destination(session->sam_socket, &session->local_dest) != 0) {
        sam_disconnect(session->sam_socket);
        session->sam_socket = -1;
        return -1;
    }
    
    // Generate a session ID
    snprintf(session->session_id, sizeof(session->session_id), "pear_%ld", (long)time(NULL));
    
    // Create a session
    if (sam_create_session(session->sam_socket, session->session_id, &session->local_dest) != 0) {
        sam_disconnect(session->sam_socket);
        session->sam_socket = -1;
        return -1;
    }
    
    return 0;
}
#else // DISABLE_I2P is defined
    // Stub implementation when I2P is disabled
    (void)session;
    (void)is_server;
    return -1;
}
#endif // DISABLE_I2P

int i2p_session_connect(i2p_session_t *session, const i2p_destination_t *remote_dest) {
#ifndef DISABLE_I2P
    if (!session || !remote_dest) {
        return -1;
    }
    
    // Lock the session
    pthread_mutex_lock(&session->mutex);
    
    // Check if already connected
    if (session->is_connected) {
        pthread_mutex_unlock(&session->mutex);
        return -1;
    }
    
    // Copy the remote destination
    memcpy(&session->remote_dest, remote_dest, sizeof(i2p_destination_t));
    
    // Send STREAM CONNECT message
    char connect_msg[BUFFER_SIZE];
    snprintf(connect_msg, sizeof(connect_msg),
             "STREAM CONNECT ID=%s DESTINATION=%s SILENT=false\n",
             session->session_id, remote_dest->base64);
    
    if (send_all(session->sam_socket, connect_msg, strlen(connect_msg), 0) < 0) {
        pthread_mutex_unlock(&session->mutex);
        return -1;
    }
    
    // Receive response
    char buffer[BUFFER_SIZE];
    ssize_t received = recv(session->sam_socket, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) {
        pthread_mutex_unlock(&session->mutex);
        return -1;
    }
    
    // Null-terminate the response
    buffer[received] = '\0';
    
    // Check if the response is OK
    if (strstr(buffer, "STREAM STATUS RESULT=OK") == NULL) {
        pthread_mutex_unlock(&session->mutex);
        return -1;
    }
    
    // Get the stream socket
    session->stream_socket = session->sam_socket;
    session->sam_socket = -1; // SAM socket is now used for streaming
    
    // Set connected flag
    session->is_connected = 1;
    
    // Unlock the session
    pthread_mutex_unlock(&session->mutex);
    
    return 0;
}
#else // DISABLE_I2P is defined
    // Stub implementation when I2P is disabled
    (void)session;
    (void)remote_dest;
    return -1;
}
#endif // DISABLE_I2P

int i2p_session_accept(i2p_session_t *session) {
#ifndef DISABLE_I2P
    if (!session) {
        return -1;
    }
    
    // Lock the session
    pthread_mutex_lock(&session->mutex);
    
    // Check if already connected
    if (session->is_connected) {
        pthread_mutex_unlock(&session->mutex);
        return -1;
    }
    
    // Send STREAM ACCEPT message
    char accept_msg[BUFFER_SIZE];
    snprintf(accept_msg, sizeof(accept_msg),
             "STREAM ACCEPT ID=%s SILENT=false\n",
             session->session_id);
    
    if (send_all(session->sam_socket, accept_msg, strlen(accept_msg), 0) < 0) {
        pthread_mutex_unlock(&session->mutex);
        return -1;
    }
    
    // Receive response
    char buffer[BUFFER_SIZE];
    ssize_t received = recv(session->sam_socket, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) {
        pthread_mutex_unlock(&session->mutex);
        return -1;
    }
    
    // Null-terminate the response
    buffer[received] = '\0';
    
    // Check if the response contains the remote destination
    char *dest_begin = strstr(buffer, "STREAM STATUS RESULT=OK DESTINATION=");
    if (!dest_begin) {
        pthread_mutex_unlock(&session->mutex);
        return -1;
    }
    
    // Extract the remote destination
    dest_begin += 35; // Skip "STREAM STATUS RESULT=OK DESTINATION="
    char *dest_end = strstr(dest_begin, "\n");
    if (!dest_end) {
        dest_end = buffer + received;
    }
    
    // Copy the remote destination
    size_t dest_len = dest_end - dest_begin;
    if (dest_len >= I2P_DEST_SIZE) {
        pthread_mutex_unlock(&session->mutex);
        return -1;
    }
    
    memcpy(session->remote_dest.base64, dest_begin, dest_len);
    session->remote_dest.base64[dest_len] = '\0';
    session->remote_dest.len = dest_len;
    
    // Get the stream socket
    session->stream_socket = session->sam_socket;
    session->sam_socket = -1; // SAM socket is now used for streaming
    
    // Set connected flag
    session->is_connected = 1;
    
    // Unlock the session
    pthread_mutex_unlock(&session->mutex);
    
    return 0;
}
#else // DISABLE_I2P is defined
    // Stub implementation when I2P is disabled
    (void)session;
    return -1;
}
#endif // DISABLE_I2P

int i2p_session_close(i2p_session_t *session) {
#ifndef DISABLE_I2P
    if (!session) {
        return -1;
    }
    
    // Lock the session
    pthread_mutex_lock(&session->mutex);
    
    // Close the stream socket
    if (session->stream_socket >= 0) {
        socket_close(session->stream_socket);
        session->stream_socket = -1;
    }
    
    // Close the SAM socket
    if (session->sam_socket >= 0) {
        socket_close(session->sam_socket);
        session->sam_socket = -1;
    }
    
    // Reset connection status
    session->is_connected = 0;
    
    // Unlock the session
    pthread_mutex_unlock(&session->mutex);
    
    // Destroy the mutex
    pthread_mutex_destroy(&session->mutex);
    
    return 0;
}
#else // DISABLE_I2P is defined
    // Stub implementation when I2P is disabled
    (void)session;
    return -1;
}
#endif // DISABLE_I2P

int i2p_session_send(i2p_session_t *session, const void *data, size_t len) {
#ifndef DISABLE_I2P
    if (!session || !data) {
        return -1;
    }
    
    // Lock the session
    pthread_mutex_lock(&session->mutex);
    
    // Check if connected
    if (!session->is_connected || session->stream_socket < 0) {
        pthread_mutex_unlock(&session->mutex);
        return -1;
    }
    
    // Send the data
    ssize_t sent = send_all(session->stream_socket, data, len, 0);
    
    // Unlock the session
    pthread_mutex_unlock(&session->mutex);
    
    return (sent < 0) ? -1 : 0;
}
#else // DISABLE_I2P is defined
    // Stub implementation when I2P is disabled
    (void)session;
    (void)data;
    (void)len;
    return -1;
}
#endif // DISABLE_I2P

int i2p_session_recv(i2p_session_t *session, void *buffer, size_t len) {
#ifndef DISABLE_I2P
    if (!session || !buffer) {
        return -1;
    }
    
    // Lock the session
    pthread_mutex_lock(&session->mutex);
    
    // Check if connected
    if (!session->is_connected || session->stream_socket < 0) {
        pthread_mutex_unlock(&session->mutex);
        return -1;
    }
    
    // Receive data
    ssize_t received = recv(session->stream_socket, buffer, len, 0);
    
    // Unlock the session
    pthread_mutex_unlock(&session->mutex);
    
    return (received < 0) ? -1 : (int)received;
}
#else // DISABLE_I2P is defined
    // Stub implementation when I2P is disabled
    (void)session;
    (void)buffer;
    (void)len;
    return -1;
}
#endif // DISABLE_I2P

/* Username-based connection */
int i2p_connect_to_username(i2p_session_t *session, const char *username) {
#ifndef DISABLE_I2P
    if (!session || !username) {
        return -1;
    }
    
    // Connect to SAM bridge for name lookup
    int sam_sock = sam_connect("127.0.0.1", sam_port);
    if (sam_sock < 0) {
        return -1;
    }
    
    // Send HELLO message
    if (sam_hello(sam_sock) != 0) {
        sam_disconnect(sam_sock);
        return -1;
    }
    
    // Look up the username
    i2p_destination_t dest;
    if (sam_lookup_name(sam_sock, username, &dest) != 0) {
        sam_disconnect(sam_sock);
        return -1;
    }
    
    // Close the SAM socket
    sam_disconnect(sam_sock);
    
    // Connect to the destination
    return i2p_session_connect(session, &dest);
}
#else // DISABLE_I2P is defined
    // Stub implementation when I2P is disabled
    (void)session;
    (void)username;
    return -1;
}
#endif // DISABLE_I2P

int i2p_register_username(i2p_session_t *session, const char *username) {
#ifndef DISABLE_I2P
    if (!session || !username) {
        return -1;
    }
    
    // Connect to SAM bridge for name registration
    int sam_sock = sam_connect("127.0.0.1", sam_port);
    if (sam_sock < 0) {
        return -1;
    }
    
    // Send HELLO message
    if (sam_hello(sam_sock) != 0) {
        sam_disconnect(sam_sock);
        return -1;
    }
    
    // Send NAMING ADD message
    char add_msg[BUFFER_SIZE];
    snprintf(add_msg, sizeof(add_msg),
             "NAMING ADD NAME=%s VALUE=%s\n",
             username, session->local_dest.base64);
    
    if (send_all(sam_sock, add_msg, strlen(add_msg), 0) < 0) {
        sam_disconnect(sam_sock);
        return -1;
    }
    
    // Receive response
    char buffer[BUFFER_SIZE];
    ssize_t received = recv(sam_sock, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) {
        sam_disconnect(sam_sock);
        return -1;
    }
    
    // Null-terminate the response
    buffer[received] = '\0';
    
    // Check if the response is OK
    if (strstr(buffer, "NAMING REPLY RESULT=OK") == NULL) {
        sam_disconnect(sam_sock);
        return -1;
    }
    
    // Close the SAM socket
    sam_disconnect(sam_sock);
    
    return 0;
}
#else // DISABLE_I2P is defined
    // Stub implementation when I2P is disabled
    (void)session;
    (void)username;
    return -1;
}
#endif // DISABLE_I2P

int i2p_unregister_username(i2p_session_t *session, const char *username) {
#ifndef DISABLE_I2P
    if (!session || !username) {
        return -1;
    }
    
    // Connect to SAM bridge for name unregistration
    int sam_sock = sam_connect("127.0.0.1", sam_port);
    if (sam_sock < 0) {
        return -1;
    }
    
    // Send HELLO message
    if (sam_hello(sam_sock) != 0) {
        sam_disconnect(sam_sock);
        return -1;
    }
    
    // Send NAMING DEL message
    char del_msg[BUFFER_SIZE];
    snprintf(del_msg, sizeof(del_msg), "NAMING DEL NAME=%s\n", username);
    
    if (send_all(sam_sock, del_msg, strlen(del_msg), 0) < 0) {
        sam_disconnect(sam_sock);
        return -1;
    }
    
    // Receive response
    char buffer[BUFFER_SIZE];
    ssize_t received = recv(sam_sock, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) {
        sam_disconnect(sam_sock);
        return -1;
    }
    
    // Null-terminate the response
    buffer[received] = '\0';
    
    // Check if the response is OK
    if (strstr(buffer, "NAMING REPLY RESULT=OK") == NULL) {
        sam_disconnect(sam_sock);
        return -1;
    }
    
    // Close the SAM socket
    sam_disconnect(sam_sock);
    
    return 0;
}
#else // DISABLE_I2P is defined
    // Stub implementation when I2P is disabled
    (void)session;
    (void)username;
    return -1;
}
#endif // DISABLE_I2P

/* Tunnel management */
int i2p_refresh_tunnels(i2p_session_t *session) {
#ifndef DISABLE_I2P
    if (!session) {
        return -1;
    }
    
    // This is a placeholder for tunnel refresh
    // In a real implementation, we would need to create a new session
    // and transfer the connection to it
    
    return 0;
}
#else // DISABLE_I2P is defined
    // Stub implementation when I2P is disabled
    (void)session;
    return -1;
}
#endif // DISABLE_I2P

/* Anti-traffic analysis */
int i2p_send_dummy_traffic(i2p_session_t *session) {
#ifndef DISABLE_I2P
    if (!session) {
        return -1;
    }
    
    // Generate random data
    unsigned char dummy[MAX_PADDING];
    randombytes_buf(dummy, sizeof(dummy));
    
    // Send the dummy data
    return i2p_session_send(session, dummy, sizeof(dummy));
}
#else // DISABLE_I2P is defined
    // Stub implementation when I2P is disabled
    (void)session;
    return -1;
}
#endif // DISABLE_I2P

int i2p_set_random_delay(i2p_session_t *session, int min_ms, int max_ms) {
#ifndef DISABLE_I2P
    if (!session) {
        return -1;
    }
    
    // This is a placeholder for setting random delay
    // In a real implementation, we would store these values in the session
    // and use them when sending messages
    
    (void)min_ms;
    (void)max_ms;
    
    return 0;
}
#else // DISABLE_I2P is defined
    // Stub implementation when I2P is disabled
    (void)session;
    (void)min_ms;
    (void)max_ms;
    return -1;
}
#endif // DISABLE_I2P
