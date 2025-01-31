# DISCLAIMER

I know very little about github, please contact me on discord for any issues or problems at "d3a_n."

This project is meant for local networks only at the moment, still working on implementing connection methods.

# pear (version 1.0)

Pear is an open-source, terminal-based, peer-to-peer encrypted chat platform. 
It enables secure communication across Windows, Linux, and macOS using advanced encryption protocols. 
Designed for both technical and non-technical users, Pear provides a simple interface to facilitate private conversations without intermediaries.

# Features

Cross-platform support: Works seamlessly on Windows, Linux, and macOS.
End-to-end encryption: Ensures that all communications are secure and private.
Command-line interface: Easy to use terminal-based interface.
Multiple cryptographic protocols: Incorporates a variety of cryptographic standards to secure data.

# Dependencies

gcc - GNU Compiler Collection
glibc/libc - Standard C libraries on Linux and macOS
Microsoft C runtime libraries - Standard libraries on Windows
POSIX Threads - Threading library for POSIX systems
Winthreads - Threading library for Windows
Winsock2 - Networking library for Windows
Libsodium - Modern, easy-to-use software library for encryption, decryption, signatures, password hashing and more
CMake - Cross-platform tool to generate makefiles and project setups

# Cryptographic Libraries

Key Exchange: Curve25519 (X25519) – crypto_kx
Symmetric Encryption: ChaCha20-Poly1305 – crypto_aead_chacha20poly1305
Authentication: Ed25519 (Digital Signatures) – crypto_sign_ed25519
Key Derivation: HKDF (HMAC-based Key Derivation Function) – crypto_kdf
Hashing: BLAKE2b – crypto_generichash
Random Number Generation: Secure PRNG – randombytes_buf

# Installation:

From Binaries:
    Visit the GitHub repository to download the latest release.
    Download the appropriate binary for your system:
        pear.exe for Windows
        pear for Linux
        pear.app for macOS
    Run the application:
        Double-click the downloaded file or launch it from the terminal by navigating to the file directory and entering ./pear.

Clone the repository:
		git clone https://github.com/d3a-n/pear
	Navigate to the project directory:
		cd pear
	Compile the source code:
		cmake .
		make

# Usage

Launch the application using the terminal or command prompt.
Enter a username when prompted. This username will be visible to others when connecting.
Choose to host a server or connect to an existing one. 
To connect, input the host's IP address and port number when prompted.
Start chatting securely.

# License

"pear" is made available under the MIT License. For more details, see the LICENSE.md file in the repository.
