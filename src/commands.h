#ifndef COMMANDS_H
#define COMMANDS_H

#include "common.h"

/*
 * process_command: Handles slash commands.
 *   /help, /clear, /status, /ping, /disconnect, /exit
 * Returns 0 if session should end, 1 otherwise.
 */
int process_command(chat_info *info, const char *input);

#endif // COMMANDS_H