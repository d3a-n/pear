#ifndef COMMANDS_H
#define COMMANDS_H

#include "common.h"

/* 
 * Processes commands entered by the user.
 * Only "/exit" is supported for this minimal 1‐on‐1 chat.
 * Returns 0 if the session should end ("/exit"), 
 *         1 otherwise.
 */
int process_command(chat_info *info, const char *input);

#endif // COMMANDS_H