#!/bin/bash

set -e

echo "==================================="
echo "Pear Linux Build Script"
echo "==================================="

# Default values
BUILD_TYPE="Release"
BUILD_DIR="build"
INSTALL_PREFIX="$BUILD_DIR/install"
JOBS=$(nproc 2>/dev/null || echo 2)
USE_SYSTEM_SODIUM="OFF"
USE_SYSTEM_I2PD="OFF"
DISABLE_I2P="OFF"
ENABLE_VERBOSE_DEBUG="ON"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --debug)
            BUILD_TYPE="Debug"
            shift
            ;;
        --release)
            BUILD_TYPE="Release"
            shift
            ;;
        --jobs=*)
            JOBS="${1#*=}"
            shift
            ;;
        --prefix=*)
            INSTALL_PREFIX="${1#*=}"
            shift
            ;;
        --system-sodium)
            USE_SYSTEM_SODIUM="ON"
            shift
            ;;
        --system-i2pd)
            USE_SYSTEM_I2PD="ON"
            shift
            ;;
        --disable-i2p)
            DISABLE_I2P="ON"
            shift
            ;;
        --no-verbose-debug)
            ENABLE_VERBOSE_DEBUG="OFF"
            shift
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --debug           Build with debug information"
            echo "  --release         Build with optimizations (default)"
            echo "  --jobs=N          Use N parallel jobs for building (default: auto)"
            echo "  --prefix=DIR      Install to DIR (default: build/install)"
            echo "  --system-sodium   Use system-installed libsodium instead of embedded"
            echo "  --system-i2pd     Use system-installed i2pd instead of embedded"
            echo "  --disable-i2p     Disable I2P support"
            echo "  --no-verbose-debug Disable verbose debug output"
            echo "  --help            Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check for required tools
command -v cmake >/dev/null 2>&1 || { echo "Error: CMake is not installed"; exit 1; }
command -v g++ >/dev/null 2>&1 || { echo "Error: g++ is not installed"; exit 1; }
command -v make >/dev/null 2>&1 || { echo "Error: make is not installed"; exit 1; }

# Detect architecture
ARCH=$(uname -m)
IS_AARCH64=false
if [ "$ARCH" = "aarch64" ]; then
    IS_AARCH64=true
    echo "Detected aarch64 architecture"
fi

# Check for required dependencies
echo "Checking for required dependencies..."

# Check for Boost
if ! pkg-config --exists libboost_system libboost_filesystem libboost_program_options; then
    echo "Warning: Boost libraries not found via pkg-config"
    echo "Will attempt to use CMake's FindBoost module"
fi

# Check for OpenSSL
if ! pkg-config --exists openssl; then
    echo "Warning: OpenSSL not found via pkg-config"
    echo "Will attempt to use CMake's FindOpenSSL module"
fi

# Check for zlib
if ! pkg-config --exists zlib; then
    echo "Warning: zlib not found via pkg-config"
    echo "Will attempt to use CMake's FindZLIB module"
fi

echo "Build configuration:"
echo "  Build type: $BUILD_TYPE"
echo "  Parallel jobs: $JOBS"
echo "  Install prefix: $INSTALL_PREFIX"

# Check if libsodium directory exists
echo "Checking libsodium directory structure..."
if [ ! -d "libsodium" ]; then
    echo "Error: libsodium directory not found."
    echo "Make sure you are running this script from the project root."
    exit 1
fi

# Check if i2pd directory exists
echo "Checking i2pd directory structure..."
if [ ! -d "i2pd" ]; then
    echo "Error: i2pd directory not found."
    echo "Make sure you are running this script from the project root."
    exit 1
fi

# Create build directory
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure with CMake
echo
echo "Configuring project with CMake..."

# Set up additional flags for aarch64 architecture
CMAKE_EXTRA_FLAGS=""
if [ "$IS_AARCH64" = true ] && [ "$USE_SYSTEM_SODIUM" = "OFF" ]; then
    echo "Adding special flags for aarch64 architecture for libsodium"
    CMAKE_EXTRA_FLAGS="-DLIBSODIUM_CFLAGS=-march=armv8-a+crypto+aes"
fi

cmake .. \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
    -DUSE_SYSTEM_SODIUM="$USE_SYSTEM_SODIUM" \
    -DUSE_SYSTEM_I2PD="$USE_SYSTEM_I2PD" \
    -DDISABLE_I2P="$DISABLE_I2P" \
    -DENABLE_VERBOSE_DEBUG="$ENABLE_VERBOSE_DEBUG" \
    $CMAKE_EXTRA_FLAGS

# Build the project
echo
echo "Building project..."
cmake --build . -- -j"$JOBS"

# Install the project
echo
echo "Installing project..."
cmake --install .

echo
echo "==================================="
echo "Build completed successfully!"
echo "==================================="
echo
echo "The executable is located at:"
echo "  $INSTALL_PREFIX/bin/pear"

cd ..
