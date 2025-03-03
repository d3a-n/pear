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

# Use pkg-config to find libsodium properly.
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSODIUM REQUIRED libsodium)

# Link Libsodium include directories and libraries.
target_include_directories(pear PRIVATE ${LIBSODIUM_INCLUDE_DIRS})
target_link_libraries(pear PRIVATE ${LIBSODIUM_LIBRARIES})

# I2PD Configuration
# Check if I2PD is available as a system library first
pkg_check_modules(I2PD IMPORTED_TARGET libi2pd)
if(I2PD_FOUND)
    message(STATUS "Using system I2PD library")
    target_link_libraries(pear PRIVATE PkgConfig::I2PD)
else()
    message(STATUS "System I2PD not found, using embedded I2PD")
    # Add I2PD as a submodule or embedded library
    # This is a placeholder - you'll need to adjust based on how I2PD is included
    # For now, we'll assume I2PD headers are in ${CMAKE_SOURCE_DIR}/i2pd/libi2pd
    if(EXISTS "${CMAKE_SOURCE_DIR}/i2pd/libi2pd")
        target_include_directories(pear PRIVATE 
            ${CMAKE_SOURCE_DIR}/i2pd
            ${CMAKE_SOURCE_DIR}/i2pd/libi2pd
            ${CMAKE_SOURCE_DIR}/i2pd/libi2pd_client
        )
        # Option to disable I2P support (useful for cross-compilation)
        option(DISABLE_I2P "Disable I2P support for Windows build" OFF)

        if(DISABLE_I2P)
            message(STATUS "I2P support explicitly disabled")
            target_compile_definitions(pear PRIVATE DISABLE_I2P)
        else()
            # Try to set up I2P dependencies
            message(STATUS "Setting up I2P dependencies")
            
            # Add I2PD source files
            file(GLOB I2PD_SOURCES 
                "${CMAKE_SOURCE_DIR}/i2pd/libi2pd/*.cpp"
                "${CMAKE_SOURCE_DIR}/i2pd/libi2pd_client/*.cpp"
            )
            target_sources(pear PRIVATE ${I2PD_SOURCES})
            
            # Check for required dependencies
            find_package(Boost COMPONENTS system filesystem program_options date_time thread)
            find_package(OpenSSL)
            find_package(ZLIB)
            
            if(Boost_FOUND AND OPENSSL_FOUND AND ZLIB_FOUND)
                # All dependencies found, enable I2P
                target_include_directories(pear PRIVATE ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
                target_link_libraries(pear PRIVATE ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} ZLIB::ZLIB)
            else()
                # Missing dependencies, disable I2P
                message(STATUS "I2P support disabled for build due to missing dependencies")
                target_compile_definitions(pear PRIVATE DISABLE_I2P)
            endif()
        endif()
    else()
        message(FATAL_ERROR "I2PD source not found at ${CMAKE_SOURCE_DIR}/i2pd. Please clone I2PD repository or install system package.")
    endif()
endif()

# Platform-specific settings.
if (WIN32)
    message(STATUS "Compiling on Windows (MinGW-w64)")
    
    # Link against Winsock2 and winpthread; ensure static linking for standard libraries.
    target_link_libraries(pear PRIVATE ws2_32 -static -Wl,-Bstatic ${LIBSODIUM_LIBRARIES} -lwinpthread -Wl,-Bdynamic)
    target_link_options(pear PRIVATE -static-libgcc -static-libstdc++)
    
    # Add Windows icon.
    message(STATUS "Adding Windows icon")
    set(WIN_ICON "${CMAKE_SOURCE_DIR}/icons/pear.ico")
    set(RC_FILE "${CMAKE_BINARY_DIR}/pear.rc")
    file(WRITE "${RC_FILE}" "IDI_ICON1 ICON \"${WIN_ICON}\"\n")
    set_source_files_properties("${RC_FILE}" PROPERTIES LANGUAGE RC)
    target_sources(pear PRIVATE "${RC_FILE}")

elseif (APPLE)
    message(STATUS "Compiling on macOS (forcing static Libsodium)")
    
    # Ensure static linking for Libsodium on macOS.
    target_link_libraries(pear PRIVATE -Wl,-Bstatic -lsodium -Wl,-Bdynamic)
    
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
    message(STATUS "Compiling on Linux (forcing static Libsodium)")
    
    # Ensure static linking for Libsodium on Linux.
    target_link_libraries(pear PRIVATE -Wl,-Bstatic -lsodium -Wl,-Bdynamic)
endif()

# Optimize Release mode.
set(CMAKE_C_FLAGS_RELEASE "-O2")
set(CMAKE_CXX_FLAGS_RELEASE "-O2")

message(STATUS "Configured to build 'pear' with sources: ${SRC_FILES}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
