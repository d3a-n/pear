#ifndef I2P_H
#define I2P_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* I2P destination structure */
typedef struct {
    char base64[I2P_DEST_SIZE];
    size_t len;
} i2p_destination_t;

/* I2P session structure */
typedef struct {
    int sam_socket;                  // Socket for SAM API communication
    i2p_destination_t local_dest;    // Local I2P destination
    i2p_destination_t remote_dest;   // Remote I2P destination
    int stream_socket;               // Socket for the established stream
    int is_connected;                // Connection status
    int is_server;                   // Whether this is a server session
    char session_id[64];             // SAM session ID
    pthread_mutex_t mutex;           // Mutex for thread safety
} i2p_session_t;

/* I2P daemon control */
int i2pd_start(void);
int i2pd_stop(void);
int i2pd_is_running(void);

/* SAM API functions */
int sam_connect(const char *sam_host, int sam_port);
int sam_disconnect(int sam_socket);
int sam_hello(int sam_socket);
int sam_generate_destination(int sam_socket, i2p_destination_t *dest);
int sam_create_session(int sam_socket, const char *session_id, const i2p_destination_t *dest);
int sam_lookup_name(int sam_socket, const char *name, i2p_destination_t *dest);
int sam_name_lookup(int sam_socket, const char *name, i2p_destination_t *dest);

/* I2P session management */
int i2p_session_init(i2p_session_t *session, int is_server);
int i2p_session_connect(i2p_session_t *session, const i2p_destination_t *remote_dest);
int i2p_session_accept(i2p_session_t *session);
int i2p_session_close(i2p_session_t *session);
int i2p_session_send(i2p_session_t *session, const void *data, size_t len);
int i2p_session_recv(i2p_session_t *session, void *buffer, size_t len);

/* Username-based connection */
int i2p_connect_to_username(i2p_session_t *session, const char *username);
int i2p_register_username(i2p_session_t *session, const char *username);
int i2p_unregister_username(i2p_session_t *session, const char *username);

/* Tunnel management */
int i2p_refresh_tunnels(i2p_session_t *session);

/* Anti-traffic analysis */
int i2p_send_dummy_traffic(i2p_session_t *session);
int i2p_set_random_delay(i2p_session_t *session, int min_ms, int max_ms);

#ifdef __cplusplus
}
#endif

#endif // I2P_H
