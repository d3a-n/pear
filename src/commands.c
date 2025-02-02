#include "commands.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Displays a help message listing available commands.
void display_help() {
    printf("[STEP] Executing /help command...\n");
    printf("Available Commands:\n");
    printf("  /help       - Display this help message\n");
    printf("  /reconnect  - Attempt to reconnect to the server\n");
    printf("  /clear      - Clear the chat screen\n");
    printf("  /exit       - Exit the chat session\n");
}

// Attempts to reconnect to the server (currently a placeholder).
void reconnect_to_server(ChatInfo *info) {
    printf("[STEP] Executing /reconnect command...\n");
    printf("[INFO] Attempting to reconnect to %s:%d...\n", info->last_host_ip, info->last_host_port);
    // (Reconnection logic would be implemented here.)
    printf("[INFO] Reconnection functionality is not implemented yet.\n");
}

// Processes a command entered by the user and executes the corresponding function.
int process_command(ChatInfo *info, const char *input) {
    char command_buf[BUFFER_SIZE];
    strncpy(command_buf, input, BUFFER_SIZE - 1);
    command_buf[BUFFER_SIZE - 1] = '\0';
    
    // Tokenize the command to determine which command to execute.
    char *token = strtok(command_buf, " ");
    if (!token)
        return 1;
    
    if (strcasecmp(token, "/help") == 0) {
        display_help();
    } else if (strcasecmp(token, "/reconnect") == 0) {
        reconnect_to_server(info);
    } else if (strcasecmp(token, "/clear") == 0) {
#ifdef _WIN32
        system("cls");
#else
        system("clear");
#endif
        printf("[STEP] Executed /clear command.\n");
    } else if (strcasecmp(token, "/exit") == 0) {
        printf("[STEP] Executing /exit command. Terminating chat session...\n");
        // The calling function should handle termination after /exit is processed.
    } else {
        printf("[WARNING] Unknown command: %s\n", token);
    }
    
    return 1;
}
