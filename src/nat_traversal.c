#include "nat_traversal.h"
#include "stun_utils.h"   // if you already have STUN utilities
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>       // close(), usleep() on Linux/macOS
#ifdef _WIN32
  #include <winsock2.h>
  #define close closesocket
#endif

/*
 * nat_get_public_info:
 *   Example using existing STUN code from "stun_utils.h".
 *   If you want to detect NAT type, call detect_nat_type() too.
 */
int nat_get_public_info(char *public_ip, size_t ip_size,
                        uint16_t *public_port)
{
    // You can pick your preferred STUN server, e.g. "stun.l.google.com", port 19302
    const char *STUN_SERVER = "stun.antisip.com";
    const uint16_t STUN_PORT = 3478;

    // Optionally detect NAT type
    int nat_result = detect_nat_type(STUN_SERVER, STUN_PORT);
    if (nat_result == NAT_TYPE_SYMMETRIC) {
        LOG_WARNING("Detected Symmetric NAT. Punching might fail without TURN.");
    } else if (nat_result == NAT_TYPE_NON_SYMMETRIC) {
        LOG_INFO("Detected NON-symmetric NAT (hole punching is more likely to succeed).");
    } else {
        LOG_WARNING("Could not detect NAT type. Continuing anyway...");
    }

    // Attempt to get public endpoint
    if (stun_get_public_address(STUN_SERVER, STUN_PORT,
                                public_ip, ip_size,
                                public_port) == 0)
    {
        LOG_INFO("Your public endpoint: %s:%u", public_ip, *public_port);
        return 0;
    } else {
        LOG_WARNING("Failed to retrieve public endpoint via STUN.");
        return -1;
    }
}

/*
 * hole_punch_udp:
 *   1. We'll attempt up to 'max_attempts' times to send 3 packets each time.
 *   2. Each packet is random length [300..600].
 *   3. We wait ~2 seconds between attempts if no success.
 *   4. If we receive anything from that remote_addr, we consider success.
 */
int hole_punch_udp(int sockfd,
                   const struct sockaddr_in *remote_addr,
                   int max_attempts)
{
    // Set up to track the remote’s IP/port for verifying inbound.
    // This depends on your platform. For brevity, we assume IPv4 only.
    char remote_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(remote_addr->sin_addr), remote_ip, sizeof(remote_ip));
    uint16_t remote_port = ntohs(remote_addr->sin_port);

    // Mark the socket “connected” so recv() only returns data from that peer.
    // Alternatively, use recvfrom() and compare the sender’s IP/port.
    if (connect(sockfd, (const struct sockaddr *)remote_addr, sizeof(*remote_addr)) < 0) {
        LOG_ERROR("connect() on UDP socket failed for hole punching.");
        return -1;
    }

    srand((unsigned)time(NULL));

    for (int attempt = 0; attempt < max_attempts; attempt++) {
        LOG_INFO("Hole punch attempt #%d ...", attempt+1);

        // Send 3 packets
        for (int i = 0; i < 3; i++) {
            // Random size between 300 and 600
            int pkt_size = 300 + (rand() % 301); 
            unsigned char *packet = (unsigned char *)malloc(pkt_size);
            if (!packet) {
                LOG_ERROR("malloc() failed for hole punch packet.");
                return -1;
            }
            // Fill with random data (not strictly required, but can help with some NATs)
            for (int p = 0; p < pkt_size; p++) {
                packet[p] = (unsigned char)(rand() & 0xFF);
            }
            ssize_t sent = send(sockfd, (const char *)packet, pkt_size, 0);
            free(packet);
            if (sent < 0) {
                LOG_WARNING("Failed to send hole punch packet (errno=%d).", errno);
                // We still continue to next packet
            }
        }

        // After sending 3 packets, wait briefly for an inbound message.
        // We'll do a small loop waiting up to ~2 seconds total.
        int wait_ms = 2000; // 2 seconds
        int step_ms = 100;  // poll every 100ms
        unsigned char buf[1024];
        while (wait_ms > 0) {
            // Use select() or poll() to see if data is available
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(sockfd, &rfds);
            struct timeval tv;
            tv.tv_sec  = step_ms / 1000;
            tv.tv_usec = (step_ms % 1000) * 1000;

#ifdef _WIN32
            int sel = select(0, &rfds, NULL, NULL, &tv);
#else
            int sel = select(sockfd+1, &rfds, NULL, NULL, &tv);
#endif
            if (sel > 0 && FD_ISSET(sockfd, &rfds)) {
                // Something arrived. Check if it’s from the correct remote (since we connect()ed).
                ssize_t rcv = recv(sockfd, (char *)buf, sizeof(buf), 0);
                if (rcv > 0) {
                    // We consider the hole “punched” 
                    LOG_INFO("Hole punch successful! Received %zd bytes from peer %s:%u",
                             rcv, remote_ip, remote_port);
                    return 0; // success
                }
            }
            wait_ms -= step_ms;
            if (wait_ms <= 0) {
                // Timed out this attempt, break out and do the next attempt
                break;
            }
        }

        LOG_INFO("No response from peer after this attempt. Will retry...");
        // Loop continues until max_attempts exhausted
    }

    LOG_ERROR("Hole punching failed after %d attempts. No response from peer.", max_attempts);
    return -1;
}