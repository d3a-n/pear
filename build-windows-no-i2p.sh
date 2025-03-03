#!/bin/bash

# Pear Windows cross-compile build script (without I2P support)

# Ensure the correct toolchain is installed
if ! which x86_64-w64-mingw32-gcc &>/dev/null; then
    echo "MinGW-w64 cross-compiler not found. Please install with:"
    echo "sudo apt install mingw-w64 g++-mingw-w64-x86-64"
    exit 1
fi

# Remove any existing build directory
rm -rf build-windows-no-i2p
mkdir -p build-windows-no-i2p
cd build-windows-no-i2p

# Configure with CMake for cross-compilation to Windows
echo "Configuring with CMake for Windows cross-compilation (without I2P)..."
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

# Create a custom CMakeLists.txt that doesn't include I2PD sources
cat > CMakeFiles/pear.dir/build.make.no_i2pd << EOF
# Modified build file to exclude I2PD files
\$(CMAKE_COMMAND) -E cmake_progress_report \$(CMAKE_BINARY_DIR)/CMakeFiles \$(CMAKE_PROGRESS_1)
\$(CMAKE_COMMAND) -E cmake_progress_report \$(CMAKE_BINARY_DIR)/CMakeFiles \$(CMAKE_PROGRESS_2)
\$(CMAKE_COMMAND) -E cmake_progress_report \$(CMAKE_BINARY_DIR)/CMakeFiles \$(CMAKE_PROGRESS_3)
EOF

# Build only our sources, not I2PD
echo "Building Pear for Windows (without I2P)..."
make -j$(nproc) src/main.cpp.obj src/chat/chat.cpp.obj src/chat/commands.cpp.obj src/chat/serialization.c.obj src/crypto/crypto.c.obj src/net/peer.cpp.obj src/net/i2p.c.obj src/logger.cpp.obj src/common.c.obj src/utils.cpp.obj

# Link the final executable
make pear.exe VERBOSE=1

# Check if the executable was created
if [ -f "pear.exe" ]; then
    echo "Build successful! The Windows executable is located at: build-windows-no-i2p/pear.exe"
else
    echo "Build failed. Please check the error messages above."
    exit 1
fi
