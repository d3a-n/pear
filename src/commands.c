#include "commands.h"
#include <strings.h>  /* or <string.h> + _stricmp if on Windows */

int process_command(chat_info *info, const char *input)
{
    (void)info; /* Not needed for single‐chat usage, but left for future expansion. */

    /* Only handle "/exit" in this minimal version. */
    if (strcasecmp(input, "/exit") == 0) {
        LOG_STEP("Executing /exit command. Terminating chat session...");
        return 0; /* Signals to end the chat loop. */
    }

    /* If any other slash command is entered, warn or ignore. */
    LOG_WARNING("Unknown command: %s", input);
    return 1;
}