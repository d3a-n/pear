#ifndef CHAT_H
#define CHAT_H

#include "common.h"

// Starts the chat session using the provided ChatInfo structure.
// This function spawns threads for sending and receiving messages with verbose logging.
void chat_session(ChatInfo *info);

// Thread function that continuously receives messages.
void *receive_messages(void *arg);

// Thread function that continuously sends messages.
void *send_messages(void *arg);

#endif // CHAT_H