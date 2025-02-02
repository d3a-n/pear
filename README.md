# Pear (Version 0.3)

**Pear** is an open-source, terminal-based, decentralized, peer-to-peer encrypted chat platform.  
It enables **fully private** communication across **Windows, Linux, and macOS** using advanced encryption and a **distributed network** with **no central servers**.  

Pear leverages:
- **DHT-based peer discovery** (KadNode)
- **Project Tox bootstrap nodes** for network entry
- **UDP Hole Punching** for NAT traversal
- **End-to-end encryption with Libsodium**
- **Dynamic, ephemeral connection keys**
- **Zero logs – ever.**

![Screenshot](screenshots/screenshot.png)

---

## Features

- **Decentralized, censorship-resistant**  
- **Zero-logging policy – no stored data**  
- **No central servers or middlemen**  
- **Peer discovery via Kademlia DHT (KadNode)**  
- **Country-based nearest node selection via [country.is](https://country.is)**  
- **Secure connections through Project Tox bootstrap nodes**  
- **NAT traversal with UDP Hole Punching**  
- **Strong encryption using Libsodium**  
- **Cross-platform: Windows, Linux, macOS**  
- **Command-line interface for efficiency**  

---

## How Pear Works

1. **DHT Lookup** – Users share their encrypted connection info using a distributed hash table (**KadNode**).  
2. **Country-Based Bootstrap** – `country.is` determines the user's country to find the nearest **Project Tox** bootstrap node.  
3. **Peer Connection** – The client queries the **DHT** for the target user’s encrypted connection info.  
4. **Decryption & NAT Traversal** – The client decrypts the retrieved connection details and uses **UDP Hole Punching** to connect.  
5. **End-to-End Encrypted Messaging** – Once connected, messages are secured using **ChaCha20-Poly1305 encryption**.  

## **Dependencies**

- **CMake** – Cross-platform build system  
- **GCC or Clang** – Compiler for C  
- **Libsodium** – Cryptography library  
- **KadNode** – Decentralized DHT-based peer lookup  
- **Curl** – HTTP requests for `country.is` API  
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
- **Secure PRNG** – **`randombytes_buf()`**  

> *Encryption is ephemeral – keys are dynamically generated and erased in memory after use.*

## Security

### **Pear is designed for total privacy:**
- **No servers.** No middlemen.
- **No logs.** Not even in memory.
- **No persistent storage.** Data exists only during runtime.
- **No metadata leakage.** Encryption prevents packet analysis.
- **No government interference.** Fully decentralized and open-source.

## Decentralized Network Stack

| **Component**  | **Function**  |
|---------------|--------------|
| **KadNode (Kademlia DHT)** | Stores & retrieves encrypted connection info |
| **Project Tox Bootstrap Nodes** | Helps users join the network |
| **Country.is API** | Determines closest Tox node |
| **UDP Hole Punching** | Bypasses NAT for direct connections |
| **Libsodium** | Encrypts all communication |


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

### **Windows (MSYS2)**

   ```sh
       pacman -S mingw-w64-x86_64-gcc 
       - mingw-w64-x86_64-pkg-config
       - mingw-w64-x86_64-libsodium 
       - mingw-w64-x86_64-cmake
       - mingw-w64-x86_64-ninja curl
   ```

### **Linux (Debian, Ubuntu, Fedora, Arch, etc.)**

   ```sh
       sudo apt install build-essential 
       - cmake 
       - ninja-build 
       - pkg-config
   ```

### macOS (Homebrew)

- **Command Line Tools**
       ```sh
       xcode-select --install
       ```
- **Required Dependencies**
       ```sh
       brew install 
       - cmake 
       - ninja 
       - libsodium
       ```

## Usage

1. Start Pear:
       ```sh
       ./pear
       ```

2. Enter a username (alphanumeric only).

3. Select a mode:

    - **Press ENTER to host a connection.**
    - **Type c to connect to a peer.**

4. Connection process:

    - **If connecting: Pear will automatically find the nearest Project Tox node and query KadNode for your peer.**
    - **If hosting: Pear will encrypt and store your connection info in the DHT.**

5. Start chatting securely.

---

## Frequently Asked Questions

### **1. How does Pear prevent tracking?**
Pear never uses a **centralized server**. All communication is handled **peer-to-peer** using **KadNode (DHT)** and **UDP Hole Punching**.

### **2. Can an attacker see my messages?**
No. All messages are **end-to-end encrypted** using **ChaCha20-Poly1305**.

### **3. Can an attacker brute-force my connection info?**
No. **Keys are ephemeral, dynamically generated, and erased after use.**

### **4. What if a peer is behind NAT?**
Pear automatically uses **UDP Hole Punching** to establish a direct connection.

### **5. How does Pear handle censorship?**
Because Pear **does not rely on central servers**, it is **censorship-resistant**.

---

## License

Pear is made available under the **MIT License**. For more details, see the [LICENSE](LICENSE) file in the repository.

---