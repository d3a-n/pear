#ifndef COMMON_H
#define COMMON_H

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <netdb.h>
  #include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sodium.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>

/* Constants */
#define BUFFER_SIZE     4096
#define USERNAME_SIZE   50
#define I2P_DEST_SIZE   516  // Base64 encoded I2P destination size
#define KEY_SIZE        32   // Size of encryption keys (256 bits)
#define NONCE_SIZE      12   // Size of ChaCha20-Poly1305 nonce
#define TAG_SIZE        16   // Size of Poly1305 authentication tag
#define MAX_PADDING     256  // Maximum random padding size
#define MIN_PADDING     16   // Minimum random padding size

/* Message types */
#define MSG_TYPE_TEXT       0x01
#define MSG_TYPE_PING       0x02
#define MSG_TYPE_PONG       0x03
#define MSG_TYPE_RATCHET    0x04
#define MSG_TYPE_DUMMY      0x05
#define MSG_TYPE_DISCONNECT 0x06

/* Exit codes */
#define EXIT_SUCCESS        0
#define EXIT_FAILURE        1
#define EXIT_CRYPTO_ERROR   2
#define EXIT_NETWORK_ERROR  3
#define EXIT_I2P_ERROR      4

/* Platform-specific socket close function */
#ifdef _WIN32
  #define socket_close(s) closesocket(s)
#else
  #define socket_close(s) close(s)
#endif

/* Secure memory functions */
#define secure_alloc(size) sodium_malloc(size)
#define secure_free(ptr) sodium_free(ptr)
#define secure_memzero(ptr, size) sodium_memzero(ptr, size)

/* Forward declarations for C++ compatibility */
#ifdef __cplusplus
extern "C" {
#endif

/* Function prototypes */
int safe_fgets(char *buffer, size_t size, FILE *stream);
ssize_t send_all(int sock, const void *buf, size_t len, int flags);
void register_exit_handlers(void);
void secure_exit(int code);

#ifdef __cplusplus
}
#endif

#endif // COMMON_H
