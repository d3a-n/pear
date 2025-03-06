#!/bin/bash

set -e

echo "==================================="
echo "Pear macOS Build Script"
echo "==================================="

# Default values
BUILD_TYPE="Release"
BUILD_DIR="build"
INSTALL_PREFIX="$BUILD_DIR/install"
JOBS=$(sysctl -n hw.ncpu 2>/dev/null || echo 2)
BUILD_BUNDLE=true
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
        --no-bundle)
            BUILD_BUNDLE=false
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
            echo "  --no-bundle       Don't build as a macOS application bundle"
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

# Check if running on macOS
if [[ "$(uname)" != "Darwin" ]]; then
    echo "Error: This script is intended to be run on macOS"
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
IS_AARCH64=false
if [ "$ARCH" = "arm64" ]; then
    IS_AARCH64=true
    echo "Detected ARM64 (Apple Silicon) architecture"
fi

# Check for required tools
command -v cmake >/dev/null 2>&1 || { echo "Error: CMake is not installed"; exit 1; }
command -v clang++ >/dev/null 2>&1 || { echo "Error: clang++ is not installed"; exit 1; }
command -v make >/dev/null 2>&1 || { echo "Error: make is not installed"; exit 1; }

# Check for Xcode command line tools
if ! xcode-select -p >/dev/null 2>&1; then
    echo "Error: Xcode command line tools are not installed"
    echo "Install them with: xcode-select --install"
    exit 1
fi

# Check for required dependencies
echo "Checking for required dependencies..."

# Check for Boost
if ! brew list --formula | grep -q "^boost$"; then
    echo "Warning: Boost not found via Homebrew"
    echo "Will attempt to use CMake's FindBoost module"
    echo "Consider installing with: brew install boost"
fi

# Check for OpenSSL
if ! brew list --formula | grep -q "^openssl@1.1$\|^openssl@3$"; then
    echo "Warning: OpenSSL not found via Homebrew"
    echo "Will attempt to use CMake's FindOpenSSL module"
    echo "Consider installing with: brew install openssl"
fi

echo "Build configuration:"
echo "  Build type: $BUILD_TYPE"
echo "  Parallel jobs: $JOBS"
echo "  Install prefix: $INSTALL_PREFIX"
echo "  Build as bundle: $BUILD_BUNDLE"

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

CMAKE_ARGS=(
    "-DCMAKE_BUILD_TYPE=$BUILD_TYPE"
    "-DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX"
)

# Add macOS-specific flags
CMAKE_ARGS+=(
    "-DCMAKE_OSX_DEPLOYMENT_TARGET=10.15"
    "-DUSE_SYSTEM_SODIUM=$USE_SYSTEM_SODIUM"
    "-DUSE_SYSTEM_I2PD=$USE_SYSTEM_I2PD"
    "-DDISABLE_I2P=$DISABLE_I2P"
    "-DENABLE_VERBOSE_DEBUG=$ENABLE_VERBOSE_DEBUG"
)

# Add special flags for ARM64 architecture
if [ "$IS_AARCH64" = true ] && [ "$USE_SYSTEM_SODIUM" = "OFF" ]; then
    echo "Adding special flags for ARM64 architecture for libsodium"
    CMAKE_ARGS+=("-DLIBSODIUM_CFLAGS=-march=armv8-a+crypto+aes")
fi

# If OpenSSL is installed via Homebrew, add its path
if brew --prefix openssl@1.1 >/dev/null 2>&1; then
    OPENSSL_ROOT_DIR=$(brew --prefix openssl@1.1)
    CMAKE_ARGS+=("-DOPENSSL_ROOT_DIR=$OPENSSL_ROOT_DIR")
elif brew --prefix openssl@3 >/dev/null 2>&1; then
    OPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
    CMAKE_ARGS+=("-DOPENSSL_ROOT_DIR=$OPENSSL_ROOT_DIR")
fi

# If Boost is installed via Homebrew, add its path
if brew --prefix boost >/dev/null 2>&1; then
    BOOST_ROOT=$(brew --prefix boost)
    CMAKE_ARGS+=("-DBOOST_ROOT=$BOOST_ROOT")
fi

cmake .. "${CMAKE_ARGS[@]}"

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

if [ "$BUILD_BUNDLE" = true ]; then
    echo "The application bundle is located at:"
    echo "  $INSTALL_PREFIX/pear.app"
    
    # Create a symlink to /Applications if requested
    read -p "Would you like to create a symlink in /Applications? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [ -e "/Applications/pear.app" ]; then
            echo "Removing existing symlink..."
            rm -f "/Applications/pear.app"
        fi
        echo "Creating symlink..."
        ln -s "$(pwd)/$INSTALL_PREFIX/pear.app" "/Applications/pear.app"
        echo "Symlink created at /Applications/pear.app"
    fi
else
    echo "The executable is located at:"
    echo "  $INSTALL_PREFIX/bin/pear"
fi

cd ..
