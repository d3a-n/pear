#!/bin/bash

# Pear Windows build script using Docker

echo "Building Pear for Windows using Docker..."

# Build the Docker image
docker build -t pear-windows-builder -f Dockerfile.windows .

# Run the Docker container to build Pear
docker run --rm -v "$(pwd):/build" pear-windows-builder

# Check if the executable was created
if [ -f "build-windows/pear.exe" ]; then
    echo "Build successful! The Windows executable is located at: build-windows/pear.exe"
else
    echo "Build failed. Check the error messages above."
    exit 1
fi
