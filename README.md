Below is the updated README reflecting all the current features of Pear:

---

# Pear (Version 0.2)

**Pear** is an open-source, terminal-based, decentralized, peer-to-peer encrypted chat platform for one-on-one communication.  
It enables **fully private** conversations across **Windows, Linux, and macOS** by using advanced, ephemeral encryption with no central servers and no stored logs.

Pear leverages:
- **End-to-end encryption with Libsodium** – dynamically generated, ephemeral keys.
- **Dynamic, ephemeral connection keys** – ensuring each session is unique.
- **Zero logs – ever.** – no data is stored or persisted.
- **Robust error handling and secure input routines** for improved reliability.
- **Multi-threaded architecture** – simultaneous sending and receiving for real-time chat.
- **A minimalist command-line interface** – streamlined for one-on-one interactions.

![Screenshot](screenshots/screenshot.png)

---

## Current Features

- **Zero-logging Policy**  
  No logs are stored on disk or retained in memory after use. Sensitive data is securely zeroed immediately when no longer needed.

- **Fully Decentralized, One-on-One Chat**  
  Peer-to-peer connections are established directly between users—there are no central servers or intermediaries.

- **Secure Ephemeral Key Exchange**  
  Uses Libsodium’s crypto_kx (based on Curve25519) for dynamic session key generation. Keys are generated for each session and securely erased afterward.

- **Strong End-to-End Encryption**  
  Messages are encrypted with ChaCha20-Poly1305 AEAD, ensuring both confidentiality and integrity.

- **Robust Error Handling and Secure Input**  
  Improved error-checking, safe input routines (via `safe_fgets`), and a helper function (`send_all`) ensure complete message transmission and secure operations.

- **Multi-threaded Send/Receive Architecture**  
  Dedicated threads handle sending and receiving messages concurrently for a seamless chat experience.

- **Cross-Platform Compatibility**  
  Fully supported on Windows, Linux, and macOS with appropriate handling for sockets, threading, and build systems.

- **CMake-Based Build System**  
  Easy-to-use and cross-platform build configuration that supports modern compilers.

- **Minimal Command Set**  
  A lightweight interface with a single supported command (`/exit`) to gracefully end a session.

---

## Upcoming

1. **Implementing STUN with libjuice** – for improved NAT traversal.
2. **Combining with LibreSSL** – to enhance cryptographic capabilities.
3. **Expanding to Multi-Peer Connections** – eventually supporting group chats and file transfers.

---

## Cryptographic Security

- **Key Exchange**  
  Ephemeral key exchange is performed using Libsodium’s crypto_kx (Curve25519) to generate unique session keys.

- **End-to-End Encryption**  
  Utilizes ChaCha20-Poly1305 AEAD, ensuring message confidentiality and integrity.

- **Secure Memory Handling**  
  All sensitive keys and data are securely zeroed from memory using dedicated routines once no longer needed.

- **Secure Random Number Generation**  
  Libsodium’s `randombytes_buf` provides a robust source of randomness for all cryptographic operations.

> *Encryption is ephemeral – keys are dynamically generated for each session and erased immediately after use.*

---

## Security

### **Designed for Total Privacy:**
- **No servers.**  
  Peer-to-peer connections mean there are no middlemen.
- **No logs.**  
  Nothing is stored on disk or retained in memory.
- **No persistent storage.**  
  All data exists only during runtime.
- **No metadata leakage.**  
  Robust encryption prevents packet analysis.
- **Robust Error Handling.**  
  The program employs safe input routines and secure messaging to guard against unexpected errors.
- **Cross-Platform Security.**  
  Trusted cryptographic libraries ensure security across all supported platforms.

---

## Installation

### From Binaries

1. Visit the [GitHub Repository](https://github.com/d3a-n/pear) and download the latest release.
2. Run the appropriate binary for your OS (or double-click the downloaded file or launch it from the terminal):
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
          mingw-w64-x86_64-ninja \
          curl
```

### Linux (Debian, Ubuntu, Fedora, Arch, etc.)

```sh
sudo apt install build-essential cmake ninja-build pkg-config
```

### macOS (Homebrew)

- **Command Line Tools**

   ```sh
   xcode-select --install
   ```

- **Required Dependencies**

   ```sh
   brew install cmake ninja libsodium
   ```

---

## Usage

1. **Start Pear:**
   ```sh
   ./pear
   ```
2. **Enter a Username**  
   Use only alphanumeric characters (underscores are allowed).

3. **Select a Mode:**
   - **Press ENTER to host a connection.**
   - **Type `c` to connect to a peer.**

4. **Connection Process:**
   - **Host Mode:**  
     Your connection details (including a dynamically assigned port) are displayed for sharing with your peer.
   - **Client Mode:**  
     You will be prompted to enter the peer's IP address and port.

5. **Start Chatting Securely!**

6. **Exit the Chat:**  
   Type `/exit` at any time to gracefully terminate the session.

---

## License

Pear is made available under the **MIT License**. For more details, see the [LICENSE](LICENSE) file in the repository.

---