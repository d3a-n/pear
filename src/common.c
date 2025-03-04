#include "../include/common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>  // Included for errno usage in send_all

/* Global flag for exit handling */
static volatile int exit_requested = 0;

/* Signal handler for graceful exit */
static void signal_handler(int sig) {
    (void)sig; // Unused parameter
    exit_requested = 1;
}

/* Safe fgets that handles errors and EOF */
int safe_fgets(char *buffer, size_t size, FILE *stream) {
    if (!buffer || size == 0 || !stream) {
        return 0;
    }

    if (fgets(buffer, size, stream) == NULL) {
        if (feof(stream)) {
            // End of file reached
            return 0;
        } else {
            // Error occurred
            return 0;
        }
    }

    return 1;
}

/* Send all data reliably */
ssize_t send_all(int sock, const void *buf, size_t len, int flags) {
    const unsigned char *ptr = (const unsigned char *)buf;
    size_t remaining = len;
    ssize_t sent;

    while (remaining > 0) {
        sent = send(sock, ptr, remaining, flags);
        if (sent <= 0) {
            if (sent < 0 && (errno == EINTR || errno == EAGAIN)) {
                continue;
            }
            return -1;
        }
        ptr += sent;
        remaining -= sent;
    }

    return (ssize_t)len;
}

/* New wrapper function for secure exit matching atexit's signature */
static void secure_exit_wrapper(void) {
    secure_exit(0);
}

/* Register exit handlers */
void register_exit_handlers(void) {
    // Register signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#ifndef _WIN32
    signal(SIGQUIT, signal_handler);
    signal(SIGHUP, signal_handler);
#endif

    // Register atexit handler with the wrapper function
    atexit(secure_exit_wrapper);
}

/* Secure exit handler */
void secure_exit(int code) {
    // Only execute once
    static int exiting = 0;
    if (exiting) {
        return;
    }
    exiting = 1;

    // Perform cleanup
    // Note: This function will be expanded as we implement more features
    
    // Exit with the provided code
    exit(code);
}

/* Check if exit has been requested */
int exit_requested_check(void) {
    return exit_requested;
}