# Pear (Version 0.3)

**Pear** is an open-source, terminal-based, decentralized, peer-to-peer encrypted chat platform for one-on-one communication. It enables **fully private** conversations across **Windows, Linux, and macOS** by using advanced, ephemeral encryption with no central servers and no stored logs.

Pear leverages:
- **End-to-end encryption with Libsodium** – Dynamically generated, ephemeral keys for every session.
- **Dynamic, ephemeral connection keys** – Each connection is uniquely secured.
- **Zero logs – Ever.** – No data is stored or persisted, ensuring total privacy.
- **Robust error handling and secure input routines** – Enhancing reliability.
- **Multi-threaded architecture** – Simultaneous sending and receiving for real-time chat.
- **A minimalist command-line interface** – Streamlined for one-on-one interactions.
- **Automatic reconnection prompts** – If a client disconnects or is rejected, it is prompted to retry or enter new connection parameters.
- **Persistent server listening** – When a connection is rejected, the server continues to listen for new incoming connections.

![Screenshot](screenshots/screenshot.png)

---

## Current Features

- **Zero-Logging Policy**  
  No logs are stored on disk or retained in memory once a session ends. Sensitive data is securely wiped immediately after use.

- **Decentralized, One-on-One Chat**  
  Establish direct peer-to-peer connections with no central servers or intermediaries.

- **Secure Ephemeral Key Exchange**  
  Uses Libsodium’s cryptographic functions (Triple Diffie-Hellman key exchange) to generate unique session keys that are securely erased after each session.

- **Strong End-to-End Encryption**  
  Messages are encrypted using ChaCha20-Poly1305 AEAD, ensuring both confidentiality and integrity.

- **Robust Error Handling and Secure Input**  
  Incorporates safe input routines (`safe_fgets`) and a helper function (`send_all`) to ensure complete and secure message transmission.

- **Multi-threaded Send/Receive Architecture**  
  Dedicated threads handle sending and receiving messages concurrently for a seamless, real-time chat experience.

- **Built-in Command Set**  
  A set of slash commands enhances usability:
  - `/help` – Display a list of available commands.
  - `/clear` – Clear the terminal screen.
  - `/status` – Show current connection status information.
  - `/ping` – Send a ping message (the remote side automatically replies with a pong).
  - `/disconnect` – Forcibly disconnect the current session.
  - `/exit` – End the chat session gracefully.

- **Automatic Reconnection Prompt (Client-Side)**  
  If the client’s connection is lost or rejected, it is prompted with:
  ```
  [INPUT] Type 'r' to retry or 'n' to enter a new IP/port:
  ```
  allowing reconnection without restarting the application.

- **Persistent Server Listening**  
  If a connection is rejected by the server, the server remains running and returns to a listening state—prompting again when a new client connects.

- **Cross-Platform Compatibility**  
  Fully supported on Windows, Linux, and macOS, with platform-specific handling for sockets, threading, and builds.

- **CMake-Based Build System**  
  A modern, cross-platform build configuration that works with current compilers.

---

## Technical Details

### Cryptography & Key Exchange

**Ephemeral Key Generation & Exchange:**
- Pear employs a **Triple Diffie-Hellman** key exchange mechanism via Libsodium.
- Each peer generates two ephemeral key pairs.
- Three Diffie-Hellman computations are performed:
  - **DH1:** `crypto_scalarmult(local_eph1_sk, remote_eph1_pk)`
  - **DH2:** `crypto_scalarmult(local_eph1_sk, remote_eph2_pk)`
  - **DH3:** `crypto_scalarmult(local_eph2_sk, remote_eph1_pk)`
- The outputs of these three operations (each 32 bytes) are concatenated into a 96-byte block and then hashed (using BLAKE2b via `crypto_generichash`) to yield a **32-byte master secret**.
- The session keys are then derived using personalization strings:
  - **Server:**  
    - Receive key (`rx_key`) = `H(master_secret, "c2s")`
    - Transmit key (`tx_key`) = `H(master_secret, "s2c")`
  - **Client:**  
    - Transmit key (`tx_key`) = `H(master_secret, "c2s")`
    - Receive key (`rx_key`) = `H(master_secret, "s2c")`
- **Debugging:**  
  By compiling with `-DDEBUG_KEYS`, ephemeral keys and final session keys are printed in hexadecimal to help verify that the server’s `tx_key` matches the client’s `rx_key` (and vice versa).

### Encryption & Message Framing

**Encryption Process:**
- **Algorithm:** Pear uses **ChaCha20-Poly1305 AEAD** (via Libsodium’s `crypto_aead_chacha20poly1305_ietf_*` functions) for encrypting messages.
- **Nonce Handling:**  
  A random 12-byte nonce is generated for each message and prepended to the ciphertext.
- **Authentication:**  
  An authentication tag is appended as part of the ciphertext to ensure message integrity.
- **Message Framing:**  
  Each message is sent with a 4-byte length prefix (in network byte order) indicating the total size of the ciphertext (nonce + encrypted data + tag). The receiver uses this prefix and `MSG_WAITALL` to ensure the full message is read before decryption.

### Threading & Message Handling

**Multi-Threaded Architecture:**
- The chat session creates two threads:
  - **Send Thread:** Reads user input, processes commands, encrypts messages, and sends them.
  - **Receive Thread:** Reads the 4-byte length prefix, then the complete ciphertext, decrypts it, and prints the received message.
- **Formatting:**  
  Received messages are printed on a new line, ensuring that the remote message does not merge with the input prompt.
- **Error Handling:**  
  If decryption fails, the receive thread prints an error message (preceded by a newline) and disconnects, ensuring the error is visible on its own line.

### Command Processing

**Built-in Slash Commands:**
- `/help` displays available commands.
- `/clear` clears the terminal screen.
- `/status` prints connection details (local and remote usernames, last known IP/port).
- `/ping` sends a ping message to which the remote peer responds with a pong.
- `/disconnect` closes the current connection immediately.
- `/exit` terminates the chat session gracefully.

### Server & Client Connection Management

**Server Behavior:**
- The server listens indefinitely for incoming connections.
- When a client connects, the server presents a prompt:  
  ```
  Client from IP <client_ip> wants to connect. Accept (y/n)?
  ```
- If the server **rejects** the connection, that client socket is closed and the server returns to listening.
- If the server **accepts** the connection, the ephemeral key exchange is performed, and the chat session begins.

**Client Behavior:**
- The client connects to a specified IP and port.
- If the connection is not accepted, the client displays:  
  ```
  [INPUT] Type 'r' to retry or 'n' to enter a new IP/port:
  ```
- This allows the user to either retry connecting or enter new connection parameters without restarting the application.

---

## Installation

### From Binaries

1. Visit the [GitHub Repository](https://github.com/d3a-n/pear) and download the latest release.
2. Run the appropriate binary for your OS:
   ```sh
   ./pear     # Linux/macOS
   pear.exe   # Windows
   ```

### Build from Source

1. Clone the repository:
   ```sh
   git clone https://github.com/d3a-n/pear
   ```
2. Navigate to the project directory:
   ```sh
   cd pear
   ```
3. Compile the source code:
   ```sh
   cmake -S . -B build
   cmake --build build
   ```

---

## Manual Compilation Dependencies

### Windows (MSYS2)

```sh
pacman -S mingw-w64-x86_64-gcc \
          mingw-w64-x86_64-pkg-config \
          mingw-w64-x86_64-libsodium \
          mingw-w64-x86_64-cmake \
          mingw-w64-x86_64-ninja
```

### Linux (Debian, Ubuntu, Fedora, Arch, etc.)

```sh
sudo apt install build-essential cmake ninja-build pkg-config
```

### macOS (Homebrew)

- **Install Command Line Tools:**
   ```sh
   xcode-select --install
   ```

- **Install Dependencies:**
   ```sh
   brew install cmake ninja libsodium
   ```

---

## Usage

1. **Start Pear:**
   ```sh
   ./pear
   ```
2. **Enter a Username:**  
   (Use only alphanumeric characters; underscores are allowed.)

3. **Select a Mode:**
   - **Host a Connection:**  
     Press **ENTER** to run as a server. The server displays its connection details (including an ephemeral port) and waits for incoming connections. When a client connects, the server is prompted to accept or reject the connection. If rejected, the server returns to listening for new connections.
   - **Connect to a Peer:**  
     Type **`c`** to run as a client. You will be prompted to enter the server’s IP address and port. If the connection fails or is rejected, you will see:
     ```
     [INPUT] Type 'r' to retry or 'n' to enter a new IP/port:
     ```
     allowing you to reconnect without restarting the application.

4. **Chat Session:**
   - Once connected and after a successful key exchange, the chat session begins.
   - Received messages are displayed on new lines, followed by a fresh input prompt.
   - Use the built-in commands for additional functionality.

5. **Built-In Commands:**
   - **`/help`** – Displays a list of available commands.
   - **`/clear`** – Clears the terminal screen.
   - **`/status`** – Shows current connection details.
   - **`/ping`** – Sends a ping to the remote peer (which replies with a pong).
   - **`/disconnect`** – Forcibly disconnects the session.
   - **`/exit`** – Gracefully terminates the chat session.

6. **Debugging Encryption Issues:**
   - If decryption fails, compile with the `DEBUG_KEYS` flag (e.g., add `-DDEBUG_KEYS` to your compiler flags or in your CMake configuration) to print the derived keys on both sides.
   - Verify that:
     - The **server’s `tx_key`** exactly matches the **client’s `rx_key`**.
     - The **server’s `rx_key`** exactly matches the **client’s `tx_key`**.
   - Matching keys indicate a proper key exchange and should result in successful encryption and decryption.

---

## License

Pear is released under the **MIT License**. For more details, see the [LICENSE](LICENSE) file in the repository.

---