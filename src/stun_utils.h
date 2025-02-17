#ifndef STUN_UTILS_H
#define STUN_UTILS_H

#include <stdint.h>
#include <stddef.h>
#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
#endif

/* Define NAT types */
#define NAT_TYPE_SYMMETRIC      1
#define NAT_TYPE_NON_SYMMETRIC  0

/*
 * stun_get_public_address:
 *   Sends a STUN Binding Request to the specified server and port,
 *   and returns the public IP and port.
 *
 * Returns 0 on success, -1 on error.
 */
int stun_get_public_address(const char *stun_server, uint16_t stun_port,
                            char *public_ip, size_t ip_size,
                            uint16_t *public_port);

/*
 * detect_nat_type:
 *   Performs two STUN queries to determine if the NAT is symmetric.
 *
 * Returns:
 *   0 if non-symmetric NAT,
 *   1 if symmetric NAT,
 *  -1 on error.
 */
int detect_nat_type(const char *stun_server, uint16_t stun_port);

#endif // STUN_UTILS_H