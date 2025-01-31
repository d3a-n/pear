cmake_minimum_required(VERSION 3.10)
project(pear C)

# Use C11
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Default to Debug if no build type specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# Enable compiler warnings
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Source files
set(SRC_FILES
    src/pear.c
)

# Create the executable (defined once)
add_executable(pear ${SRC_FILES})

# Find and link Threads (pthread on Linux/Mac)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(pear PRIVATE Threads::Threads)

# Link with libsodium
target_link_libraries(pear PRIVATE sodium)

# Platform-specific links
if(WIN32)
    target_link_libraries(pear PRIVATE ws2_32)
    # If you want static linking of runtime, un-comment:
    # set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")
elseif(APPLE)
    message(STATUS "Compiling on macOS")
else()
    message(STATUS "Compiling on Linux/Unix")
endif()

# Windows icon handling (fixed)
if(WIN32)
    message(STATUS "Adding Windows icon")
    set(WIN_ICON "${CMAKE_SOURCE_DIR}/icons/pear.ico")
    set(RC_FILE "${CMAKE_BINARY_DIR}/pear.rc")
    
    # Write the resource file
    file(WRITE "${RC_FILE}" "IDI_ICON1 ICON \"${WIN_ICON}\"\n")

    # Add resource file to compilation
    set_source_files_properties("${RC_FILE}" PROPERTIES LANGUAGE RC)
    target_sources(pear PRIVATE "${RC_FILE}")
endif()

# macOS icon handling (fixed)
if(APPLE)
    message(STATUS "Adding macOS icon")
    set(MACOSX_BUNDLE_ICON_FILE "pear.icns")
    set_source_files_properties(${CMAKE_SOURCE_DIR}/icons/pear.icns
        PROPERTIES MACOSX_PACKAGE_LOCATION "Resources")

    set_target_properties(pear PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_ICON_FILE ${MACOSX_BUNDLE_ICON_FILE}
    )
endif()

# (Optional) Release mode optimization
set(CMAKE_C_FLAGS_RELEASE "-O2")

# Installation step on Linux if desired:
# if(UNIX AND NOT APPLE)
#     install(TARGETS pear DESTINATION /usr/local/bin)
# endif

message(STATUS "Configured to build 'pear' with source: ${SRC_FILES}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# Ensure static linking where needed
target_link_libraries(pear PRIVATE ws2_32 -static -lsodium)