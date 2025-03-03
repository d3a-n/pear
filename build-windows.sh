#!/bin/bash

# Pear Windows cross-compile build script

# Ensure the correct toolchain is installed
if ! which x86_64-w64-mingw32-gcc &>/dev/null; then
    echo "MinGW-w64 cross-compiler not found. Please install with:"
    echo "sudo apt install mingw-w64 g++-mingw-w64-x86-64"
    exit 1
fi

# Create build directory
mkdir -p build-windows
cd build-windows

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
    -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY

# Build
echo "Building Pear for Windows..."
make -j$(nproc)

# Check if build was successful
if [ $? -eq 0 ]; then
    echo "Build successful! The Windows executable is located at: build-windows/pear.exe"
else
    echo "Build failed. Please check the error messages above."
    exit 1
fi
