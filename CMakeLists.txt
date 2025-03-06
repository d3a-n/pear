cmake_minimum_required(VERSION 3.10)
project(pear LANGUAGES C CXX)

# Add cmake modules path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Use the C11 and C++17 standards
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Default to Debug if no build type is specified.
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# Build options
option(USE_SYSTEM_SODIUM "Use system-installed libsodium instead of embedded" ON)
option(USE_SYSTEM_I2PD "Use system-installed i2pd instead of embedded" OFF)
option(DISABLE_I2P "Disable I2P support" OFF)
option(ENABLE_VERBOSE_DEBUG "Enable verbose debug output" ON)
set(LIBSODIUM_CFLAGS "" CACHE STRING "Additional CFLAGS for libsodium")

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
    # src/net/i2p.c - Removed to avoid duplicate definitions with i2p_wrapper.cpp
    src/net/i2p_wrapper.cpp
    src/logger.cpp
    src/common.c
    src/utils.cpp
)

# Create the executable.
add_executable(pear ${SRC_FILES})

# Enable verbose debug if option is turned on
if(ENABLE_VERBOSE_DEBUG)
    message(STATUS "Verbose debug output enabled")
    target_compile_definitions(pear PRIVATE ENABLE_VERBOSE_DEBUG)
endif()

# Include directories.
target_include_directories(pear PRIVATE 
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)

# Find and link pthreads (on Linux/macOS) or winpthreads on Windows.
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(pear PRIVATE Threads::Threads)

# Handle libsodium dependency
if(USE_SYSTEM_SODIUM)
    message(STATUS "Using system-installed libsodium")
    find_package(Sodium REQUIRED)
    target_link_libraries(pear PRIVATE Sodium::Sodium)
else()
    message(STATUS "Building embedded libsodium")
    
    # Pass additional CFLAGS to libsodium if specified
    if(NOT "${LIBSODIUM_CFLAGS}" STREQUAL "")
        message(STATUS "Using additional CFLAGS for libsodium: ${LIBSODIUM_CFLAGS}")
        set(LIBSODIUM_CFLAGS "${LIBSODIUM_CFLAGS}" CACHE STRING "Additional CFLAGS for libsodium" FORCE)
    endif()
    
    # Add SODIUM_STATIC definition to the main project
    target_compile_definitions(pear PRIVATE SODIUM_STATIC)
    
    # Use add_subdirectory to properly build libsodium
    add_subdirectory(${CMAKE_SOURCE_DIR}/libsodium)
    
    # Link the sodium library to the main executable
    target_link_libraries(pear PRIVATE sodium)
    
    # Add include directories for the main executable
    target_include_directories(pear PRIVATE
        ${CMAKE_SOURCE_DIR}/libsodium/src/libsodium/include
        ${CMAKE_SOURCE_DIR}/libsodium/src/libsodium/include/sodium
    )
endif()

# Handle i2pd dependency
if(DISABLE_I2P)
    message(STATUS "I2P support explicitly disabled")
    target_compile_definitions(pear PRIVATE DISABLE_I2P)
elseif(USE_SYSTEM_I2PD)
    message(STATUS "Using system-installed i2pd")
    find_package(I2PD REQUIRED)
    target_link_libraries(pear PRIVATE I2PD::I2PD)
    
    # Disable i18n support to avoid undefined reference errors
    target_compile_definitions(pear PRIVATE DISABLE_I18N)
else()
    message(STATUS "Building embedded I2PD")
    add_subdirectory(${CMAKE_SOURCE_DIR}/i2pd)
    target_link_libraries(pear PRIVATE i2pd)
    
    # Disable i18n support to avoid undefined reference errors
    target_compile_definitions(pear PRIVATE DISABLE_I18N)
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
