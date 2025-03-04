cmake_minimum_required(VERSION 3.10)
project(pear LANGUAGES C CXX)

# Use the C11 and C++17 standards
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Default to Debug if no build type is specified.
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# Enable compiler warnings.
if (MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# List source files
set(SRC_FILES
    src/main.cpp
    src/chat/chat.cpp
    src/chat/commands.cpp
    src/chat/serialization.c
    src/crypto/crypto.c
    src/net/peer.cpp
    src/net/i2p.c
    src/logger.cpp
    src/common.c
    src/utils.cpp
)

# Create the executable.
add_executable(pear ${SRC_FILES})

# Include directories.
target_include_directories(pear PRIVATE 
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)

# Find and link pthreads (on Linux/macOS) or winpthreads on Windows.
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(pear PRIVATE Threads::Threads)

# Build embedded libsodium
message(STATUS "Building embedded libsodium")
add_subdirectory(${CMAKE_SOURCE_DIR}/libsodium)
target_link_libraries(pear PRIVATE sodium)

# Build embedded I2PD
message(STATUS "Building embedded I2PD")
add_subdirectory(${CMAKE_SOURCE_DIR}/i2pd)
target_link_libraries(pear PRIVATE i2pd)

# Disable i18n support to avoid undefined reference errors
target_compile_definitions(pear PRIVATE DISABLE_I18N)

# Option to disable I2P support (useful for cross-compilation)
option(DISABLE_I2P "Disable I2P support for Windows build" OFF)
if(DISABLE_I2P)
    message(STATUS "I2P support explicitly disabled")
    target_compile_definitions(pear PRIVATE DISABLE_I2P)
endif()

# Platform-specific settings.
if (WIN32)
    message(STATUS "Compiling on Windows (MinGW-w64)")
    
    # Link against Winsock2 and winpthread; ensure static linking for standard libraries.
    target_link_libraries(pear PRIVATE ws2_32 -static -Wl,-Bstatic -lwinpthread -Wl,-Bdynamic)
    target_link_options(pear PRIVATE -static-libgcc -static-libstdc++)
    
    # Add Windows icon.
    message(STATUS "Adding Windows icon")
    set(WIN_ICON "${CMAKE_SOURCE_DIR}/icons/pear.ico")
    set(RC_FILE "${CMAKE_BINARY_DIR}/pear.rc")
    file(WRITE "${RC_FILE}" "IDI_ICON1 ICON \"${WIN_ICON}\"\n")
    set_source_files_properties("${RC_FILE}" PROPERTIES LANGUAGE RC)
    target_sources(pear PRIVATE "${RC_FILE}")

elseif (APPLE)
    message(STATUS "Compiling on macOS")
    
    # Add macOS icon.
    message(STATUS "Adding macOS icon")
    set(MACOSX_BUNDLE_ICON_FILE "pear.icns")
    set_source_files_properties(${CMAKE_SOURCE_DIR}/icons/pear.icns
        PROPERTIES MACOSX_PACKAGE_LOCATION "Resources")
    set_target_properties(pear PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_ICON_FILE ${MACOSX_BUNDLE_ICON_FILE}
    )

elseif (UNIX)
    message(STATUS "Compiling on Linux")
endif()

# Optimize Release mode.
set(CMAKE_C_FLAGS_RELEASE "-O2")
set(CMAKE_CXX_FLAGS_RELEASE "-O2")

message(STATUS "Configured to build 'pear' with sources: ${SRC_FILES}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
