uses UDP hole punching, and triple diffie hellman, along with a wide variety of encryption methods. 

list of commands:

`/help` – displays commands
`/clear` – clear terminal
`/status` – show connection status
`/ping` – sends a ping message
`/disconnect` – terminates session
`/exit` – closes application

build using cmake:

needs libsodium as a dependency

cmake -B build
cmake --build build