# Pear Build System

This directory contains build scripts for compiling Pear on different operating systems. These scripts handle the configuration, building, and installation of Pear, including the embedded i2pd and libsodium libraries.

## Quick Start

### Windows

```cmd
build-windows.bat
```

### Linux

```bash
./build-linux.sh
```

### macOS

```bash
./build-macos.sh
```

## Detailed Instructions

For detailed build instructions, including available options and troubleshooting tips, please see the [BUILD.md](BUILD.md) file.

## Build Scripts

- `build-windows.bat`: Windows build script (works with Visual Studio or MinGW)
- `build-linux.sh`: Linux build script
- `build-macos.sh`: macOS build script
- `cmake/FindSodium.cmake`: CMake module for finding libsodium
- `cmake/FindI2PD.cmake`: CMake module for finding i2pd

## Features

- Automatic detection of build tools and compilers
- Support for both debug and release builds
- Options for using system-installed libraries instead of embedded ones
- Platform-specific optimizations and configurations
- Proper handling of dependencies

## Dependencies

Pear depends on the following libraries:

1. **i2pd**: For I2P networking functionality
2. **libsodium**: For cryptographic operations

The build scripts handle these dependencies automatically, either by building the embedded versions or by using system-installed versions if requested.
