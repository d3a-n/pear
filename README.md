---

# Pear (Version 0.3)

**Pear** is an open-source, terminal-based, decentralized, peer-to-peer encrypted chat platform for one-on-one communication. It enables **fully private** conversations across **Windows, Linux, and macOS** by using advanced, ephemeral encryption with no central servers and no stored logs.

Pear leverages:
- **End-to-end encryption with Libsodium** – Dynamically generated, ephemeral keys for every session.
- **Dynamic, ephemeral connection keys** – Each connection is uniquely secured.
- **Zero logs – Ever.** – No data is stored or persisted, ensuring total privacy.
- **Robust error handling and secure input routines** – Enhancing reliability.
- **Multi-threaded architecture** – Simultaneous sending and receiving for real-time chat.
- **A minimalist command-line interface** – Streamlined for one-on-one interactions.

![Screenshot](screenshots/screenshot.png)

---

## Current Features

- **Zero-Logging Policy**  
  No logs are stored on disk or retained in memory once a session ends. Sensitive data is securely wiped immediately after use.

- **Decentralized, One-on-One Chat**  
  Establish direct peer-to-peer connections with no central servers or intermediaries.

- **Secure Ephemeral Key Exchange**  
  Uses Libsodium’s `crypto_kx` (Curve25519/X25519) for dynamic session key generation. Each session uses unique keys that are securely erased once the session terminates.

- **Strong End-to-End Encryption**  
  Messages are encrypted using ChaCha20-Poly1305 AEAD, ensuring both confidentiality and integrity.

- **Robust Error Handling and Secure Input**  
  Incorporates safe input routines (`safe_fgets`) and a helper function (`send_all`) to ensure complete, secure message transmission.

- **Multi-threaded Send/Receive Architecture**  
  Dedicated threads handle sending and receiving messages concurrently for a seamless, real-time chat experience.

- **Cross-Platform Compatibility**  
  Fully supported on Windows, Linux, and macOS, with platform-specific handling for sockets, threading, and builds.

- **CMake-Based Build System**  
  A modern, cross-platform build configuration that works with current compilers.

- **Minimal Command Set**  
  A lightweight interface with a single command (`/exit`) to gracefully terminate a session.

---

## Upcoming Features

1. **STUN Integration with libjuice** – For improved NAT traversal.
2. **Enhanced Cryptographic Capabilities with LibreSSL** – Additional security and interoperability.
3. **Multi-Peer Connections** – Future support for group chats and file transfers.

---

## Cryptographic Usages

- **Cryptographic Library:**  
  [Libsodium](https://libsodium.gitbook.io/doc/)

- **Key Exchange:**  
  Curve25519 (X25519) via Libsodium’s `crypto_kx`.

- **Symmetric Encryption:**  
  ChaCha20-Poly1305 using Libsodium’s `crypto_aead_chacha20poly1305`.

- **Authentication:**  
  Ed25519 digital signatures via Libsodium’s `crypto_sign_ed25519`.

- **Key Derivation:**  
  HKDF (HMAC-based Key Derivation Function) via Libsodium’s `crypto_kdf`.

- **Hashing:**  
  BLAKE2b via Libsodium’s `crypto_generichash`.

- **Random Number Generation:**  
  Secure PRNG using Libsodium’s `randombytes_buf`.

> *Encryption is ephemeral – keys are dynamically generated for each session and securely erased after use.*

---

## Security Overview

### Designed for Total Privacy:
- **No Servers:**  
  Direct peer-to-peer connections eliminate middlemen.
- **No Logs:**  
  Nothing is stored on disk or retained in memory.
- **No Persistent Storage:**  
  Data exists only during runtime.
- **No Metadata Leakage:**  
  Robust encryption minimizes exposure to packet analysis.
- **Robust Error Handling:**  
  The program employs safe input routines and secure messaging to mitigate unexpected errors.
- **Cross-Platform Security:**  
  Trusted cryptographic libraries ensure security on all supported platforms.

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

- **Install Required Dependencies:**

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
   (Use only alphanumeric characters; underscores are allowed.)

3. **Select a Mode:**
   - **Host a Connection:**  
     Press **ENTER** to host a connection. Your connection details (including a dynamically assigned port) will be displayed for sharing with your peer.
   - **Connect to a Peer:**  
     Type `c` to connect. You will be prompted to enter your peer's IP address and port.

4. **Start Chatting Securely!**

5. **Exit the Chat:**  
   Type `/exit` at any time to gracefully terminate your session.

---

## License

Pear is released under the **MIT License**. For more details, see the [LICENSE](LICENSE) file in the repository.

---