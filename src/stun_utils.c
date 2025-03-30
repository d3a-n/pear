/* stun_utils.c
 *
 * A fully working STUN client implementation that communicates with
 * the Antisip STUN server (stun.antisip.com:3478) to retrieve your public IP and port.
 * It also performs a basic NAT type detection by comparing two consecutive queries.
 *
 * Compile with -DTEST_STUN to run the test main().
 */

#include "stun_utils.h"
#include "common.h"  // For LOG_INFO, LOG_ERROR, etc.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #define close closesocket
#else
  #include <sys/socket.h>
  #include <netdb.h>
  #include <unistd.h>
#endif

#define STUN_HEADER_SIZE 20   // 20-byte header for STUN messages

/* Generate a random Transaction ID (12 bytes) */
static void generate_transaction_id(uint8_t *tid, size_t len) {
    /* For production, consider a better randomness source than time(NULL) */
    srand((unsigned int)time(NULL));
    for (size_t i = 0; i < len; i++) {
        tid[i] = (uint8_t)(rand() & 0xFF);
    }
}

/* Build a STUN Binding Request. */
static int build_stun_request(uint8_t *buf, size_t *len) {
    if (*len < STUN_HEADER_SIZE)
        return -1;
    memset(buf, 0, *len);
    // Message Type: Binding Request (0x0001)
    buf[0] = 0x00;
    buf[1] = 0x01;
    // Message Length: 0 (no attributes)
    buf[2] = 0x00;
    buf[3] = 0x00;
    // Magic Cookie: 0x2112A442
    buf[4] = 0x21;
    buf[5] = 0x12;
    buf[6] = 0xA4;
    buf[7] = 0x42;
    // Transaction ID: 12 random bytes
    generate_transaction_id(&buf[8], 12);
    *len = STUN_HEADER_SIZE;
    return 0;
}

/* Parse the STUN response to extract the mapped IP and port.
 * It looks for either MAPPED-ADDRESS (0x0001) or XOR-MAPPED-ADDRESS (0x0020).
 */
static int parse_stun_response(const uint8_t *buf, size_t len,
                               char *mapped_ip, size_t ip_size,
                               uint16_t *mapped_port)
{
    if (len < STUN_HEADER_SIZE)
        return -1;
    // Check for Binding Success Response (0x0101)
    uint16_t msg_type = (buf[0] << 8) | buf[1];
    if (msg_type != 0x0101)
        return -1;
    
    size_t pos = STUN_HEADER_SIZE;
    while (pos + 4 <= len) {
        uint16_t attr_type = (buf[pos] << 8) | buf[pos + 1];
        uint16_t attr_len  = (buf[pos + 2] << 8) | buf[pos + 3];
        pos += 4;
        if (pos + attr_len > len)
            break;
        if (attr_type == 0x0001 || attr_type == 0x0020) {
            if (attr_len >= 8) {
                /* Structure:
                 *   Byte 0: ignore
                 *   Byte 1: address family (1 for IPv4)
                 *   Bytes 2-3: port (possibly XORed)
                 *   Bytes 4-7: IP address (possibly XORed)
                 */
                uint16_t port = (buf[pos + 2] << 8) | buf[pos + 3];
                uint32_t ip;
                memcpy(&ip, &buf[pos + 4], 4);
                if (attr_type == 0x0001) {
                    *mapped_port = ntohs(port);
                    struct in_addr ia;
                    memcpy(&ia, &ip, sizeof(ia));
                    inet_ntop(AF_INET, &ia, mapped_ip, ip_size);
                } else {  // XOR-MAPPED-ADDRESS
                    uint32_t magic_cookie = htonl(0x2112A442);
                    uint16_t xport = port ^ htons(0x2112);
                    *mapped_port = ntohs(xport);
                    uint32_t xip = ip ^ magic_cookie;
                    struct in_addr ia;
                    memcpy(&ia, &xip, sizeof(ia));
                    inet_ntop(AF_INET, &ia, mapped_ip, ip_size);
                }
                return 0;
            }
        }
        pos += attr_len;
        if (attr_len % 4 != 0)
            pos += 4 - (attr_len % 4);
    }
    return -1;
}

/*
 * stun_get_public_address:
 *   Sends a STUN Binding Request to the specified STUN server and port,
 *   then receives and parses the response to determine the public IP and port.
 */
int stun_get_public_address(const char *stun_server, uint16_t stun_port,
                            char *public_ip, size_t ip_size,
                            uint16_t *public_port)
{
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;      // IPv4 only
    hints.ai_socktype = SOCK_DGRAM;   // UDP

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", stun_port);
    if (getaddrinfo(stun_server, port_str, &hints, &res) != 0 || !res) {
        fprintf(stderr, "[STUN] getaddrinfo() failed for %s:%d\n", stun_server, stun_port);
        return -1;
    }
    int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0) {
        perror("[STUN] socket() failed");
        freeaddrinfo(res);
        return -1;
    }
    if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("[STUN] connect() failed");
        freeaddrinfo(res);
#ifdef _WIN32
        closesocket(sockfd);
#else
        close(sockfd);
#endif
        return -1;
    }
    freeaddrinfo(res);

    uint8_t request[512];
    size_t req_len = sizeof(request);
    if (build_stun_request(request, &req_len) < 0) {
        fprintf(stderr, "[STUN] build_stun_request() failed.\n");
#ifdef _WIN32
        closesocket(sockfd);
#else
        close(sockfd);
#endif
        return -1;
    }
    if (send(sockfd, (const char*)request, (int)req_len, 0) < 0) {
        perror("[STUN] send() failed");
#ifdef _WIN32
        closesocket(sockfd);
#else
        close(sockfd);
#endif
        return -1;
    }
    uint8_t response[512];
    int r = recv(sockfd, (char*)response, sizeof(response), 0);
    if (r < 0) {
        perror("[STUN] recv() failed");
#ifdef _WIN32
        closesocket(sockfd);
#else
        close(sockfd);
#endif
        return -1;
    }
    if (parse_stun_response(response, r, public_ip, ip_size, public_port) < 0) {
        fprintf(stderr, "[STUN] parse_stun_response() failed.\n");
#ifdef _WIN32
        closesocket(sockfd);
#else
        close(sockfd);
#endif
        return -1;
    }
#ifdef _WIN32
    closesocket(sockfd);
#else
    close(sockfd);
#endif
    return 0;
}

/*
 * detect_nat_type:
 *   Performs two STUN queries using separate UDP sockets.
 *   If the public IP/port from both queries are identical, returns NAT_TYPE_NON_SYMMETRIC;
 *   otherwise, returns NAT_TYPE_SYMMETRIC.
 */
int detect_nat_type(const char *stun_server, uint16_t stun_port)
{
    char ip1[64], ip2[64];
    uint16_t port1 = 0, port2 = 0;
    if (stun_get_public_address(stun_server, stun_port, ip1, sizeof(ip1), &port1) != 0)
        return -1;
    if (stun_get_public_address(stun_server, stun_port, ip2, sizeof(ip2), &port2) != 0)
        return -1;
    if (port1 == port2 && strcmp(ip1, ip2) == 0)
        return NAT_TYPE_NON_SYMMETRIC;
    return NAT_TYPE_SYMMETRIC;
}

#ifdef TEST_STUN
int main(void) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed.\n");
        return 1;
    }
#endif

    char public_ip[64] = {0};
    uint16_t public_port = 0;
    if (stun_get_public_address(STUN_SERVER, STUN_PORT, public_ip, sizeof(public_ip), &public_port) == 0) {
        printf("Public endpoint: %s:%u\n", public_ip, public_port);
    } else {
        printf("Failed to get public endpoint via STUN.\n");
    }

    int nat_type = detect_nat_type(STUN_SERVER, STUN_PORT);
    if (nat_type == NAT_TYPE_SYMMETRIC)
        printf("NAT Type: Symmetric\n");
    else if (nat_type == NAT_TYPE_NON_SYMMETRIC)
        printf("NAT Type: Non-Symmetric\n");
    else
        printf("NAT Type: Unknown/Error\n");

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
#endif