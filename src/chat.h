#ifndef CHAT_H
#define CHAT_H

#include "common.h"

/*
 * Launches sending and receiving threads.
 */
void chat_session(chat_info *info);

/*
 * Receiving thread: reads length-prefixed ciphertext, decrypts, handles ping/pong, etc.
 */
void *receive_messages(void *arg);

/*
 * Sending thread: reads user input, processes slash commands, encrypts messages, sends them.
 */
void *send_messages(void *arg);

#endif // CHAT_H