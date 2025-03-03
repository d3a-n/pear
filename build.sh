#!/bin/bash

# Pear build script

# Create build directory
mkdir -p build
cd build

# Configure with CMake
echo "Configuring with CMake..."
cmake ..

# Build
echo "Building Pear..."
make -j$(nproc)

# Check if build was successful
if [ $? -eq 0 ]; then
    echo "Build successful! The executable is located at: build/pear"
    echo "Run it with: ./pear"
else
    echo "Build failed. Please check the error messages above."
    exit 1
fi
