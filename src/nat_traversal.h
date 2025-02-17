#ifndef NAT_TRAVERSAL_H
#define NAT_TRAVERSAL_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
#endif

#include "common.h"

/*
 * nat_get_public_info:
 *   Uses STUN to get your public IP/port.
 *   Optionally, it can detect your NAT type.
 * Returns 0 on success, -1 on error.
 */
int nat_get_public_info(char *public_ip, size_t ip_size,
                        uint16_t *public_port);

/*
 * hole_punch_udp:
 *   Attempts UDP hole punching by sending three packets of random size
 *   (between 300 and 600 bytes) to the remote address. If no response is
 *   received, it waits 2 seconds and sends three more. This repeats for a
 *   given number of attempts.
 *
 * Returns 0 if a response is received (hole punch successful) or -1 on failure.
 */
int hole_punch_udp(int sockfd,
                   const struct sockaddr_in *remote_addr,
                   int max_attempts);

#endif // NAT_TRAVERSAL_H