# Pear (Version 0.1)

**Pear** is an open-source, terminal-based, peer-to-peer encrypted chat platform.
It enables secure communication across Windows, Linux, and macOS using advanced encryption protocols.
Designed for both technical and non-technical users, Pear provides a simple interface to facilitate private conversations without intermediaries.

![Screenshot](screenshots/screenshot.png)

## Features

- **Cross-platform support**: Works seamlessly on Windows, Linux, and macOS.
- **End-to-end encryption**: Ensures that all communications are secure and private.
- **Command-line interface**: Easy-to-use terminal-based interface.
- **Multiple cryptographic protocols**: Incorporates a variety of cryptographic standards to secure data.

## Dependencies

- **GCC**: GNU Compiler Collection
- **glibc/libc**: Standard C libraries on Linux and macOS
- **Microsoft C Runtime Libraries**: Standard libraries on Windows
- **POSIX Threads**: Threading library for POSIX systems
- **Winthreads**: Threading library for Windows
- **Winsock2**: Networking library for Windows
- **Libsodium**: Modern, easy-to-use software library for encryption, decryption, signatures, password hashing, and more
- **CMake**: Cross-platform tool to generate makefiles and project setups

> *Excluding Windows dependencies, all are open-source.*

## Cryptographic Libraries

- **Cryptographic Library**: Libsodium
- **Key Exchange**: Curve25519 (X25519) – `crypto_kx`
- **Symmetric Encryption**: ChaCha20-Poly1305 – `crypto_aead_chacha20poly1305`
- **Authentication**: Ed25519 (Digital Signatures) – `crypto_sign_ed25519`
- **Key Derivation**: HKDF (HMAC-based Key Derivation Function) – `crypto_kdf`
- **Hashing**: BLAKE2b – `crypto_generichash`
- **Random Number Generation**: Secure PRNG – `randombytes_buf`

## Security

- Resistant to all known methods of decryption, including quantum attacks to an extent.
- All encryption methods are open-source with no known backdoors or government influence.
- Keys are dynamically created and destroyed, even in memory.
- **No logs are kept under ANY circumstances.**

## Installation

### From Binaries

1. Visit the [GitHub repository](https://github.com/d3a-n/pear) to download the latest release.
2. Download the appropriate binary for your system:
   - `pear.exe` for Windows
   - `pear` for Linux
   - `pear.app` for macOS
3. Run the application:
   - Double-click the downloaded file or launch it from the terminal:
     ```sh
     ./pear
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
   cmake .
   make
   ```

## Manual Compilation Dependencies

### **Windows (MSYS2)**
- **GCC** (`mingw-w64-x86_64-gcc`)
- **pkg-config** (`mingw-w64-x86_64-pkg-config`)
- **Libsodium** (`mingw-w64-x86_64-libsodium`)
- **CMake** (`mingw-w64-x86_64-cmake`)
- **Ninja (`mingw-w64-x86_64-ninja`)**

### **Linux (Debian, Ubuntu, Fedora, Arch, etc.)**
- **GCC and Build Tools**
  ```sh
  sudo apt install build-essential cmake ninja-build pkg-config

## **macOS (Homebrew)**

- **Command Line Tools**
   ```sh
   xcode-select --install
- **Required Dependencies**
   ```sh
   brew install cmake ninja libsodium

## Usage

1. Launch the application using the terminal or command prompt.
2. Enter a username when prompted. This username will be visible to others when connecting.
3. Choose to **host a server** or **connect to an existing one**.
4. To connect, input the host's IP address and port number when prompted.
5. Start chatting securely.

## License

Pear is made available under the **MIT License**. For more details, see the [LICENSE](LICENSE) file in the repository.