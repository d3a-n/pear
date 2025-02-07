#include "common.h"

/* send_all: ensures the entire buffer is sent, handling partial sends. */
ssize_t send_all(int sock, const void *buf, size_t len, int flags)
{
    size_t total_sent = 0;
    const char *data = (const char *)buf;

    while (total_sent < len) {
        ssize_t sent = send(sock, data + total_sent, len - total_sent, flags);
        if (sent <= 0) {
            /* Retry on EINTR/EAGAIN, else error out. */
            if (sent < 0 && (errno == EINTR || errno == EAGAIN)) {
                continue;
            }
            return -1;
        }
        total_sent += sent;
    }
    return (ssize_t)total_sent;
}

/* safe_fgets: reads a line safely, flushing extra characters if needed. */
int safe_fgets(char *buffer, size_t size, FILE *stream)
{
    if (fgets(buffer, size, stream) == NULL) {
        return 0;
    }
    /* If there's no newline, flush the remainder of the line. */
    if (strchr(buffer, '\n') == NULL) {
        int ch;
        while ((ch = fgetc(stream)) != '\n' && ch != EOF)
            ;
    }
    return 1;
}