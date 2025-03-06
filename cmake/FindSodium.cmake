# FindSodium.cmake
# ----------------
#
# Find the native libsodium library.
#
# This will define the following variables:
#
#  Sodium_FOUND            - True if libsodium was found
#  Sodium_INCLUDE_DIRS     - Include directories for libsodium
#  Sodium_LIBRARIES        - Libraries to link against for libsodium
#
# This will also define the following imported targets:
#
#  Sodium::Sodium          - The libsodium library

# Find include directory
find_path(Sodium_INCLUDE_DIR
  NAMES sodium.h
  PATH_SUFFIXES sodium
  DOC "libsodium include directory"
)

# Find library
find_library(Sodium_LIBRARY
  NAMES sodium libsodium
  DOC "libsodium library"
)

# Set standard find_package variables
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Sodium
  REQUIRED_VARS Sodium_LIBRARY Sodium_INCLUDE_DIR
)

# Set output variables
set(Sodium_LIBRARIES ${Sodium_LIBRARY})
set(Sodium_INCLUDE_DIRS ${Sodium_INCLUDE_DIR})

# Create imported target
if(Sodium_FOUND AND NOT TARGET Sodium::Sodium)
  add_library(Sodium::Sodium UNKNOWN IMPORTED)
  set_target_properties(Sodium::Sodium PROPERTIES
    IMPORTED_LOCATION "${Sodium_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${Sodium_INCLUDE_DIR}"
  )
endif()

mark_as_advanced(Sodium_INCLUDE_DIR Sodium_LIBRARY)
