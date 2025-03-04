cmake_minimum_required(VERSION 3.10)
project(sodium C)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include/sodium
    ${CMAKE_CURRENT_BINARY_DIR}/src/libsodium/include
)

# Define source files
file(GLOB_RECURSE SODIUM_SOURCES 
    ${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/*.c
)

# Exclude test files and non-relevant platform files
list(FILTER SODIUM_SOURCES EXCLUDE REGEX ".*test.*\\.c$")
list(FILTER SODIUM_SOURCES EXCLUDE REGEX ".*bench.*\\.c$")

# Platform-specific configurations
if(WIN32)
    add_definitions(-DWINVER=0x0600 -D_WIN32_WINNT=0x0600)
    list(FILTER SODIUM_SOURCES EXCLUDE REGEX ".*unix.*\\.c$")
else()
    list(FILTER SODIUM_SOURCES EXCLUDE REGEX ".*windows.*\\.c$")
endif()

# Create version header
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include/sodium/version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/src/libsodium/include/sodium/version.h
)

# Create library
add_library(sodium STATIC ${SODIUM_SOURCES})

# Set compile definitions
target_compile_definitions(sodium PRIVATE
    CONFIGURED
    NATIVE_LITTLE_ENDIAN
    HAVE_STDLIB_H
    HAVE_STRING_H
    HAVE_INTTYPES_H
    HAVE_STDINT_H
    HAVE_SYS_TYPES_H
)

# Platform-specific compile definitions
if(WIN32)
    target_compile_definitions(sodium PRIVATE
        _CRT_SECURE_NO_WARNINGS
        SODIUM_STATIC
        SODIUM_EXPORT=
    )
else()
    target_compile_definitions(sodium PRIVATE
        HAVE_PTHREAD
        HAVE_MMAP
        HAVE_MLOCK
        HAVE_MADVISE
        HAVE_NANOSLEEP
    )
endif()

# Set include directories for consumers of this library
target_include_directories(sodium PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/src/libsodium/include>
    $<INSTALL_INTERFACE:include>
)

# Installation rules (if needed)
if(FALSE) # Disabled for now as we're using it as a subproject
    install(TARGETS sodium
        EXPORT sodiumConfig
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin
    )

    install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include/
        DESTINATION include
        FILES_MATCHING PATTERN "*.h"
    )

    install(EXPORT sodiumConfig
        DESTINATION share/sodium
        NAMESPACE Sodium::
    )
endif()
