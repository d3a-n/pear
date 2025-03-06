# Building Pear

This document provides instructions for building Pear on different operating systems.

## Prerequisites

### All Platforms
- CMake 3.10 or higher
- C++17 compatible compiler
- Git (for cloning the repository)

### Windows
- Visual Studio 2019/2022 with C++ workload OR MinGW-w64
- Windows SDK

### Linux
- GCC 7.0+ or Clang 6.0+
- Development packages for:
  - Boost (system, filesystem, program_options)
  - OpenSSL
  - zlib
  - pthread

### macOS
- Xcode Command Line Tools
- Homebrew (recommended for installing dependencies)
- Boost, OpenSSL, and zlib (can be installed via Homebrew)

## Building

We provide build scripts for each platform that handle the build process, including configuring CMake, building the project, and installing it.

### Windows

Run the `build-windows.bat` script:

```cmd
build-windows.bat [options]
```

Options:
- `--debug`: Build with debug information
- `--release`: Build with optimizations (default)
- `--x86`: Build for 32-bit architecture
- `--x64`: Build for 64-bit architecture (default)
- `--system-sodium`: Use system-installed libsodium instead of embedded
- `--system-i2pd`: Use system-installed i2pd instead of embedded
- `--disable-i2p`: Disable I2P support
- `--help`: Show help message

The script will automatically detect Visual Studio or MinGW and use the appropriate generator.

### Linux

Run the `build-linux.sh` script:

```bash
./build-linux.sh [options]
```

Options:
- `--debug`: Build with debug information
- `--release`: Build with optimizations (default)
- `--jobs=N`: Use N parallel jobs for building (default: auto)
- `--prefix=DIR`: Install to DIR (default: build/install)
- `--system-sodium`: Use system-installed libsodium instead of embedded
- `--system-i2pd`: Use system-installed i2pd instead of embedded
- `--disable-i2p`: Disable I2P support
- `--help`: Show help message

### macOS

Run the `build-macos.sh` script:

```bash
./build-macos.sh [options]
```

Options:
- `--debug`: Build with debug information
- `--release`: Build with optimizations (default)
- `--jobs=N`: Use N parallel jobs for building (default: auto)
- `--prefix=DIR`: Install to DIR (default: build/install)
- `--no-bundle`: Don't build as a macOS application bundle
- `--system-sodium`: Use system-installed libsodium instead of embedded
- `--system-i2pd`: Use system-installed i2pd instead of embedded
- `--disable-i2p`: Disable I2P support
- `--help`: Show help message

## Manual Building

If you prefer to build manually using CMake, you can follow these steps:

### Windows (Visual Studio)

```cmd
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64 ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DUSE_SYSTEM_SODIUM=OFF ^
    -DUSE_SYSTEM_I2PD=OFF ^
    -DDISABLE_I2P=OFF
cmake --build . --config Release
```

### Windows (MinGW)

```cmd
mkdir build
cd build
cmake .. -G "MinGW Makefiles" ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DUSE_SYSTEM_SODIUM=OFF ^
    -DUSE_SYSTEM_I2PD=OFF ^
    -DDISABLE_I2P=OFF
cmake --build .
```

### Linux/macOS

```bash
mkdir build
cd build
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DUSE_SYSTEM_SODIUM=OFF \
    -DUSE_SYSTEM_I2PD=OFF \
    -DDISABLE_I2P=OFF
cmake --build . -- -j$(nproc)
```

You can set any of the following CMake options to customize the build:

- `-DUSE_SYSTEM_SODIUM=ON/OFF`: Use system-installed libsodium instead of embedded
- `-DUSE_SYSTEM_I2PD=ON/OFF`: Use system-installed i2pd instead of embedded
- `-DDISABLE_I2P=ON/OFF`: Disable I2P support
- `-DCMAKE_BUILD_TYPE=Debug/Release`: Build with debug information or optimizations
- `-DCMAKE_INSTALL_PREFIX=path`: Install to the specified path

## Dependencies

Pear embeds two key libraries:

1. **i2pd**: For I2P networking functionality
2. **libsodium**: For cryptographic operations

The build scripts and CMake configuration handle the building and linking of these libraries automatically.

### Using System-Installed Libraries

By default, Pear builds and links against the embedded versions of i2pd and libsodium. However, you can choose to use system-installed versions of these libraries instead:

#### libsodium

To use a system-installed version of libsodium, pass the `--system-sodium` flag to the build script. The system must have libsodium development files installed:

- **Windows**: Install libsodium via vcpkg, MSYS2/MinGW, or build it manually
  ```cmd
  # Using vcpkg
  git clone https://github.com/Microsoft/vcpkg.git
  cd vcpkg
  .\bootstrap-vcpkg.bat
  .\vcpkg install libsodium:x64-windows  # or x86-windows for 32-bit
  .\vcpkg integrate install
  ```
- **Linux**: Install the libsodium development package
  ```bash
  # Debian/Ubuntu
  sudo apt-get install libsodium-dev
  
  # Fedora
  sudo dnf install libsodium-devel
  
  # Arch Linux
  sudo pacman -S libsodium
  ```
- **macOS**: Install libsodium via Homebrew
  ```bash
  brew install libsodium
  ```

##### Installing libsodium from source

If you prefer to install libsodium from source, follow these steps:

```bash
# Download and extract the latest stable version
wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.18.tar.gz
tar -xf libsodium-1.0.18.tar.gz
cd libsodium-1.0.18

# Configure and build
./configure
make && make check
sudo make install

# On Linux, update the dynamic linker
sudo ldconfig
```

On aarch64 platforms, you may need to specify additional flags:

```bash
# For aarch64 platforms
env CFLAGS="$CFLAGS -march=armv8-a+crypto+aes" ./configure
make && make check
sudo make install
sudo ldconfig
```

Note: Our build scripts automatically detect aarch64 platforms and apply the appropriate flags when building the embedded libsodium.

#### i2pd

To use a system-installed version of i2pd, pass the `--system-i2pd` flag to the build script. The system must have i2pd development files installed:

- **Linux**: Install the i2pd development package (if available) or build it from source
- **macOS**: Install i2pd via Homebrew (if available) or build it from source

Note that using system-installed i2pd may be less reliable than using the embedded version, as the API compatibility between different versions is not guaranteed.

### Disabling I2P Support

If you don't need I2P networking functionality, you can disable it by passing the `--disable-i2p` flag to the build script. This can be useful for:

- Reducing build time and binary size
- Avoiding dependency on Boost and other i2pd requirements
- Cross-compilation scenarios where i2pd support is problematic

## Troubleshooting

### Common Issues

#### Windows
- If you encounter errors about missing libraries, make sure you have the required Visual Studio components installed.
- For MinGW builds, ensure you're using a compatible version (preferably MinGW-w64 with POSIX threads).

#### Linux
- If CMake fails to find Boost, OpenSSL, or zlib, install the development packages:
  ```bash
  # Debian/Ubuntu
  sudo apt-get install libboost-all-dev libssl-dev zlib1g-dev
  
  # Fedora
  sudo dnf install boost-devel openssl-devel zlib-devel
  
  # Arch Linux
  sudo pacman -S boost openssl zlib
  ```

#### macOS
- If you encounter issues with OpenSSL, install it via Homebrew and specify its path:
  ```bash
  brew install openssl
  ```
  The build script should automatically detect the Homebrew OpenSSL installation.

#### i2pd Compilation Issues
- If you encounter an error about 'netID' being redeclared, the build scripts include a fix that adds a `-DNETID_INTERNAL` define to the i2pd CMakeLists.txt file. This is automatically applied when you run the build scripts.
- If you're building manually, you can run the `fix-i2pd.sh` (Linux/macOS) or `fix-i2pd.bat` (Windows) script before building to apply this fix.

### Build Logs

If you encounter build failures, check the CMake and build logs for detailed error messages. These logs can be found in the build directory.
