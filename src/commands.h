#ifndef COMMANDS_H
#define COMMANDS_H

#include "common.h"

// Processes a command entered by the user.
// Supported commands: /help, /reconnect, /clear, and /exit.
int process_command(ChatInfo *info, const char *input);

// Displays a help message with available commands.
void display_help();

// Attempts to reconnect to the server.
void reconnect_to_server(ChatInfo *info);

#endif // COMMANDS_H