#ifndef CHAT_H
#define CHAT_H

#include "common.h"

/*
 * Starts the chat session using the provided chat_info structure.
 * Spawns threads for sending and receiving messages.
 */
void chat_session(chat_info *info);

/* Thread function that continuously receives messages. */
void *receive_messages(void *arg);

/* Thread function that continuously sends messages. */
void *send_messages(void *arg);

#endif // CHAT_H