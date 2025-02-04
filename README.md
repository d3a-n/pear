# Pear (Version 0.2)

**Pear** is an open-source, terminal-based, decentralized, peer-to-peer encrypted chat platform.  
It enables **fully private** communication across **Windows, Linux, and macOS** using advanced encryption and a **distributed network** with **no central servers**.  

Pear leverages:
- **End-to-end encryption with Libsodium**
- **Dynamic, ephemeral connection keys**
- **Zero logs – ever.**

![Screenshot](screenshots/screenshot.png)

## UPCOMING

1. Implementing STUN with libjuice.
2. Combining with libressl.
3. Using libsodium with it all for secure connections.

## Features
 
- **Zero-logging policy – no stored data**  
- **Secure connections through libjuice (UPCOMING)**   
- **Strong encryption using Libsodium**  
- **Cross-platform: Windows, Linux, macOS**  
- **Command-line interface for efficiency**  

---

## **Dependencies**

- **CMake** – Cross-platform build system  
- **GCC or Clang** – Compiler for C  
- **Libsodium** – Cryptography library   
- **POSIX Threads** – Threading for Linux/macOS  
- **WinThreads** – Threading for Windows  
- **Winsock2** – Windows networking support  

> *Everything is open-source except for the Microsoft runtime libraries (Windows only).*

## Cryptographic Security

- **Key Exchange** – **Curve25519 (X25519)**  
- **End-to-End Encryption** – **ChaCha20-Poly1305 (AEAD)**  
- **Authentication** – **Ed25519 digital signatures**  
- **Key Derivation** – **HKDF**  
- **Hashing** – **BLAKE2b**  
- **Secure PRNG** – **randombytes_buf**  

> *Encryption is ephemeral – keys are dynamically generated and erased in memory after use.*

## Security

### **Pear is designed for total privacy:**
- **No servers.** No middlemen.
- **No logs.** Not even in memory.
- **No persistent storage.** Data exists only during runtime.
- **No metadata leakage.** Encryption prevents packet analysis.
- **No government interference.** Fully decentralized and open-source.

## Installation

### From Binaries

1. Visit the [GitHub Repository](https://github.com/d3a-n/pear) and download the latest release.
2. Run the appropriate binary for your OS (or double-click the downloaded file or launch it from the terminal):
   ```sh
   ./pear     # Linux/macOS
   pear.exe   # Windows

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
   cmake .
   make
   ```

## Manual Compilation Dependencies

### Windows (MSYS2)

   ```sh
       pacman -S mingw-w64-x86_64-gcc 
       - mingw-w64-x86_64-pkg-config
       - mingw-w64-x86_64-libsodium 
       - mingw-w64-x86_64-cmake
       - mingw-w64-x86_64-ninja curl
   ```

### Linux (Debian, Ubuntu, Fedora, Arch, etc.)

   ```sh
       sudo apt install build-essential 
       - cmake 
       - ninja-build 
       - pkg-config
   ```

### macOS (Homebrew)

- **Command Line Tools**

       xcode-select --install
       ```

- **Required Dependencies**

       brew install 
       - cmake 
       - ninja 
       - libsodium

## Usage

1. Start Pear:

       ./pear

2. Enter a username (alphanumeric only).

3. Select a mode:

    - **Press ENTER to host a connection.**
    - **Type c to connect to a peer.**

4. Connection process:

    - **If connecting: Pear will prompt you to enter a username and connect o a peer. (UPCOMING)**
    - **If hosting: Pear will encrypt and store your connection info in a STUN server, and when retrieved will ask permission to decrypt. (UPCOMING)**

5. Start chatting securely.

---

## License

Pear is made available under the **MIT License**. For more details, see the [LICENSE](LICENSE) file in the repository.

---
