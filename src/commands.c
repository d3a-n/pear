#include "commands.h"
#include "crypto_utils.h"
#include <strings.h> // for strcasecmp

#ifdef _WIN32
  #define CLEAR_COMMAND "cls"
#else
  #define CLEAR_COMMAND "clear"
#endif

static void show_help(void) {
    LOG_INFO("Available Commands:");
    LOG_INFO("  /help        - Show this help message");
    LOG_INFO("  /clear       - Clear the chat screen");
    LOG_INFO("  /status      - Show connection status info");
    LOG_INFO("  /ping        - Send a ping message");
    LOG_INFO("  /disconnect  - Forcibly disconnect");
    LOG_INFO("  /exit        - Exit the chat session");
}

static void show_status(chat_info *info) {
    LOG_INFO("Local Username: %s", info->local_username);
    LOG_INFO("Remote Username: %s", info->remote_username);
    LOG_INFO("Last Known IP: %s, Port: %d", info->last_host_ip, info->last_host_port);
}

int process_command(chat_info *info, const char *input) {
    if (strcasecmp(input, "/help") == 0) {
        show_help();
        return 1;
    }
    else if (strcasecmp(input, "/clear") == 0) {
        system(CLEAR_COMMAND);
        LOG_INFO("Screen cleared.");
        return 1;
    }
    else if (strcasecmp(input, "/status") == 0) {
        show_status(info);
        return 1;
    }
    else if (strcasecmp(input, "/ping") == 0) {
        const char *ping_marker = "\x01PING\x01";
        unsigned char ciphertext[BUFFER_SIZE + 64];
        size_t ciphertext_len = 0;
        if (encrypt_message((const unsigned char *)ping_marker, strlen(ping_marker),
                            info->tx_key, ciphertext, &ciphertext_len) == 0)
        {
            if (send_all(info->sock, ciphertext, ciphertext_len, 0) == (ssize_t)ciphertext_len)
                LOG_INFO("Ping sent.");
            else
                LOG_ERROR("Failed to send complete ping message.");
        } else {
            LOG_ERROR("Encryption failed. Ping not sent.");
        }
        return 1;
    }
    else if (strcasecmp(input, "/disconnect") == 0) {
        LOG_STEP("Disconnecting the current session...");
        socket_close(info->sock);
        return 0; // ends the session
    }
    else if (strcasecmp(input, "/exit") == 0) {
        LOG_STEP("User requested /exit. Terminating chat session...");
        return 0;
    }
    else {
        LOG_WARNING("Unknown command: %s", input);
        return 1;
    }
}