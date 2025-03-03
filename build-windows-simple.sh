#!/bin/bash

# Pear Windows cross-compile build script (simplified version)

# Ensure the correct toolchain is installed
if ! which x86_64-w64-mingw32-gcc &>/dev/null; then
    echo "MinGW-w64 cross-compiler not found. Please install with:"
    echo "sudo apt install mingw-w64 g++-mingw-w64-x86-64"
    exit 1
fi

# Create build directory
mkdir -p build-windows-simple
cd build-windows-simple

# Configure with CMake for cross-compilation to Windows
echo "Configuring with CMake for Windows cross-compilation..."
cmake .. \
    -DCMAKE_SYSTEM_NAME=Windows \
    -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc \
    -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++ \
    -DCMAKE_RC_COMPILER=x86_64-w64-mingw32-windres \
    -DCMAKE_FIND_ROOT_PATH=/usr/x86_64-w64-mingw32 \
    -DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER \
    -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY \
    -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY \
    -DDISABLE_I2P=ON \
    -DCMAKE_BUILD_TYPE=Release

# Build
echo "Building Pear for Windows..."
make -j$(nproc) VERBOSE=1 || make VERBOSE=1

# Check if build was successful
if [ $? -eq 0 ]; then
    echo "Build successful! The Windows executable is located at: build-windows-simple/pear.exe"
else
    echo "Build failed. Please check the error messages above."
    exit 1
fi
