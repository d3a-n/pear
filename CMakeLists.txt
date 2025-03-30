cmake_minimum_required(VERSION 3.10)
project(pear C)

# Use the C11 standard.
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

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

# List source files (ensure these files exist in the "src" folder).
set(SRC_FILES
    src/main.c
    src/crypto_utils.c
    src/commands.c
    src/chat.c
    src/common.c
    src/nat_traversal.c
    src/stun_utils.c
)

# Create the executable.
add_executable(pear ${SRC_FILES})

# Include directories.
target_include_directories(pear PRIVATE ${CMAKE_SOURCE_DIR}/src)

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

message(STATUS "Configured to build 'pear' with sources: ${SRC_FILES}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")