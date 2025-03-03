#include "common.h"

int safe_fgets(char *buffer, size_t size, FILE *stream) {
    if (!fgets(buffer, size, stream))
        return 0;
    if (!strchr(buffer, '\n')) {
        int ch;
        while ((ch = fgetc(stream)) != '\n' && ch != EOF)
            ;
    }
    return 1;
}

ssize_t send_all(int sock, const void *buf, size_t len, int flags) {
    size_t total_sent = 0;
    const unsigned char *data = (const unsigned char *)buf;
    while (total_sent < len) {
        ssize_t sent = send(sock, (const char *)(data + total_sent), len - total_sent, flags);
        if (sent <= 0) {
            if (sent < 0 && (errno == EINTR || errno == EAGAIN))
                continue;
            return -1;
        }
        total_sent += sent;
    }
    return (ssize_t)total_sent;
}