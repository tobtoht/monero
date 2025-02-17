#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "hidapi::hidraw" for configuration "Release"
set_property(TARGET hidapi::hidraw APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(hidapi::hidraw PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "C"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libhidapi-hidraw.a"
  )

list(APPEND _cmake_import_check_targets hidapi::hidraw )
list(APPEND _cmake_import_check_files_for_hidapi::hidraw "${_IMPORT_PREFIX}/lib/libhidapi-hidraw.a" )

# Import target "hidapi::libusb" for configuration "Release"
set_property(TARGET hidapi::libusb APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(hidapi::libusb PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "C"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libhidapi-libusb.a"
  )

list(APPEND _cmake_import_check_targets hidapi::libusb )
list(APPEND _cmake_import_check_files_for_hidapi::libusb "${_IMPORT_PREFIX}/lib/libhidapi-libusb.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
