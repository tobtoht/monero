# Main options
OPTION(USE_DEVICE_TREZOR "Trezor support compilation" ON)
OPTION(USE_DEVICE_TREZOR_MANDATORY "Trezor compilation is mandatory, fail build if Trezor support cannot be compiled" OFF)
OPTION(USE_DEVICE_TREZOR_LIBUSB "Trezor LibUSB compilation" ON)
OPTION(USE_DEVICE_TREZOR_UDP_RELEASE "Trezor UdpTransport in release mode" OFF)
OPTION(USE_DEVICE_TREZOR_DEBUG "Trezor Debugging enabled" OFF)
OPTION(TREZOR_DEBUG "Main Trezor debugging switch" OFF)

macro(trezor_fatal_msg msg)
    if ($ENV{USE_DEVICE_TREZOR_MANDATORY})
        message(FATAL_ERROR
                "${msg}\n"
                "==========================================================================\n"
                "[ERROR] To compile without Trezor support, set USE_DEVICE_TREZOR=OFF. "
                "It is possible both via cmake variable and environment variable, e.g., "
                "`USE_DEVICE_TREZOR=OFF make release`\n"
                "For more information, please check src/device_trezor/README.md\n"
        )
    else()
        message(WARNING
                "${msg}\n"
                "==========================================================================\n"
                "[WARNING] Trezor support cannot be compiled! Skipping Trezor compilation. \n"
                "For more information, please check src/device_trezor/README.md\n")
        set(USE_DEVICE_TREZOR OFF)
        return()  # finish this cmake file processing (as this is macro).
    endif()
endmacro()

# Use Trezor master switch
if (NOT USE_DEVICE_TREZOR)
    message(STATUS "Trezor: support disabled by USE_DEVICE_TREZOR")
else()
    # Look for ProtobufConfig.cmake, provided by Protobuf
    find_package(Protobuf CONFIG)

    # Look for FindProtobuf.cmake, provided by CMake
    if (NOT Protobuf_FOUND)
        find_package(Protobuf)
    endif()

    if (NOT Protobuf_FOUND)
        trezor_fatal_msg("Trezor library not found")
    endif()
endif()

# Try to build protobuf messages
if(Protobuf_FOUND AND USE_DEVICE_TREZOR)
    find_program(Protobuf_PROTOC_EXECUTABLE protoc REQUIRED)

    if(TREZOR_DEBUG)
        set(USE_DEVICE_TREZOR_DEBUG 1)
        message(STATUS "Trezor: debug build enabled")
        # Compile debugging support (for tests)
        add_definitions(-DWITH_TREZOR_DEBUGGING=1)
    endif()

    # .proto files to compile
    set(_proto_files "messages.proto"
                     "messages-common.proto"
                     "messages-management.proto"
                     "messages-monero.proto")
    if (TREZOR_DEBUG)
        list(APPEND _proto_files "messages-debug.proto")
    endif ()

    set(_include_dir "${CMAKE_CURRENT_LIST_DIR}/../external/trezor-common/protob")
    set(_proto_files_absolute)
    foreach(file IN LISTS _proto_files)
        list(APPEND _proto_files_absolute "${_include_dir}/${file}")
    endforeach ()

    execute_process(COMMAND ${Protobuf_PROTOC_EXECUTABLE} --cpp_out "${CMAKE_CURRENT_LIST_DIR}/../src/device_trezor/trezor/messages" "-I${_include_dir}" ${_proto_files_absolute} RESULT_VARIABLE RET OUTPUT_VARIABLE OUT ERROR_VARIABLE ERR)
    if(RET)
        trezor_fatal_msg("Trezor: protobuf messages could not be (re)generated (err=${RET}). OUT: ${OUT}, ERR: ${ERR}.")
    endif()

    message(STATUS "Trezor: protobuf messages regenerated")
    set(DEVICE_TREZOR_READY 1)
    add_definitions(-DDEVICE_TREZOR_READY=1)
    add_definitions(-DPROTOBUF_INLINE_NOT_IN_HEADERS=0)

    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_definitions(-DTREZOR_DEBUG=1)
    endif()

    if(USE_DEVICE_TREZOR_UDP_RELEASE)
        message(STATUS "Trezor: UDP transport enabled (emulator)")
        add_definitions(-DUSE_DEVICE_TREZOR_UDP_RELEASE=1)
    endif()

    if (Protobuf_INCLUDE_DIR)
        include_directories(${Protobuf_INCLUDE_DIR})
    endif()

    # LibUSB support, check for particular version
    # Include support only if compilation test passes
    if (USE_DEVICE_TREZOR_LIBUSB)
        find_package(LibUSB)
    endif()

    if (LibUSB_COMPILE_TEST_PASSED)
        add_definitions(-DHAVE_TREZOR_LIBUSB=1)
        if(LibUSB_INCLUDE_DIRS)
            include_directories(${LibUSB_INCLUDE_DIRS})
        endif()
    endif()

    set(TREZOR_LIBUSB_LIBRARIES "")
    if(LibUSB_COMPILE_TEST_PASSED)
        list(APPEND TREZOR_LIBUSB_LIBRARIES ${LibUSB_LIBRARIES} ${LIBUSB_DEP_LINKER})
        message(STATUS "Trezor: compatible LibUSB found at: ${LibUSB_INCLUDE_DIRS}")
    elseif(USE_DEVICE_TREZOR_LIBUSB AND NOT ANDROID)
        trezor_fatal_msg("Trezor: LibUSB not found or test failed, please install libusb-1.0.26")
    endif()
endif()
