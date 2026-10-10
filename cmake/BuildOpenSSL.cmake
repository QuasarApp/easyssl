#
# Copyright (C) 2025-2025 QuasarApp.
# Distributed under the GPLv3 software license, see the accompanying
# Everyone is permitted to copy and distribute verbatim copies
# of this license document, but changing it is not allowed.
#

# This file clones the OpenSSL sources and builds the OpenSSL libraries
# before the easyssl library is built. It is included only when the
# BUILD_WITH_OPENSSL option is enabled.
#
# Supported platforms: Linux, Android, iOS and macOS (arm/x86).
# The Windows and WASM platforms are not supported.

include_guard()

include(ExternalProject)

set(EASYSSL_OPENSSL_TAG "openssl-3.0.9" CACHE STRING
    "The OpenSSL git tag that will be cloned and built with the project")

set(EASYSSL_OPENSSL_DIR "${CMAKE_BINARY_DIR}/openssl-build" CACHE PATH
    "The directory where the OpenSSL sources and the build results are stored")

set(EASYSSL_OPENSSL_INSTALL_DIR "${EASYSSL_OPENSSL_DIR}/install" CACHE PATH
    "The prefix directory where the OpenSSL libraries are installed")

# The OpenSSL build options. The libraries are built as static, because
# they will be linked privately into the easyssl library.
set(_easyssl_openssl_options
    -no-shared
    -no-tests
    -no-ui-console
    -no-ssl3
    -no-comp
    -no-engine
    --libdir=lib
)

# Select the OpenSSL configure target and the extra environment variables
# for the current build platform.
set(_easyssl_openssl_target "")
set(_easyssl_openssl_env "")

if (ANDROID)

    # The OpenSSL android targets use the ANDROID_NDK_HOME environment
    # variable to find the NDK toolchain.
    set(_easyssl_openssl_env "ANDROID_NDK_HOME=${CMAKE_ANDROID_NDK}")

    if (CMAKE_ANDROID_API_LEVEL)
        list(APPEND _easyssl_openssl_env "ANDROID_API_VERSION=${CMAKE_ANDROID_API_LEVEL}")
    endif()

    # Map the current ANDROID_ABI to the OpenSSL configure target.
    if (ANDROID_ABI STREQUAL "arm64-v8a")
        set(_easyssl_openssl_target "android-arm64")
    elseif (ANDROID_ABI STREQUAL "armeabi-v7a")
        set(_easyssl_openssl_target "android-arm")
    elseif (ANDROID_ABI STREQUAL "x86_64")
        set(_easyssl_openssl_target "android-x86_64")
    elseif (ANDROID_ABI STREQUAL "x86")
        set(_easyssl_openssl_target "android-x86")
    else()
        message(FATAL_ERROR "The ANDROID_ABI '${ANDROID_ABI}' is not supported by the BUILD_WITH_OPENSSL option")
    endif()

elseif (IOS)

    # The OpenSSL ios targets need the CROSS_TOP and CROSS_SDK environment
    # variables with the xcode developer path and the SDK name.
    get_filename_component(_easyssl_ios_sdk_name "${CMAKE_OSX_SYSROOT}" NAME)
    get_filename_component(_easyssl_ios_sdks_dir "${CMAKE_OSX_SYSROOT}" DIRECTORY)
    get_filename_component(_easyssl_ios_cross_top "${_easyssl_ios_sdks_dir}" DIRECTORY)

    set(_easyssl_openssl_env
        "CROSS_TOP=${_easyssl_ios_cross_top}"
        "CROSS_SDK=${_easyssl_ios_sdk_name}"
    )

    if (CMAKE_OSX_ARCHITECTURES STREQUAL "arm64")
        set(_easyssl_openssl_target "ios64-cross")
    elseif (CMAKE_OSX_ARCHITECTURES STREQUAL "armv7")
        set(_easyssl_openssl_target "ios-cross")
    else()
        message(FATAL_ERROR "The iOS architecture '${CMAKE_OSX_ARCHITECTURES}' is not supported by the BUILD_WITH_OPENSSL option (the iOS simulator is not supported)")
    endif()

elseif (APPLE)

    # The macOS host build.
    if (CMAKE_OSX_ARCHITECTURES MATCHES "arm64")
        set(_easyssl_openssl_target "darwin64-arm64-cc")
    else()
        set(_easyssl_openssl_target "darwin64-x86_64-cc")
    endif()

else()

    # The Linux and other unix-like host builds.
    if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        set(_easyssl_openssl_target "linux-aarch64")
    elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
        set(_easyssl_openssl_target "linux-x86_64")
    else()
        message(FATAL_ERROR "The processor '${CMAKE_SYSTEM_PROCESSOR}' is not supported by the BUILD_WITH_OPENSSL option")
    endif()

endif()

if (NOT _easyssl_openssl_target)
    message(FATAL_ERROR "Can not select the OpenSSL target for the current build platform")
endif()

message(STATUS "The BUILD_WITH_OPENSSL option is enabled. The OpenSSL ${EASYSSL_OPENSSL_TAG} will be built for the '${_easyssl_openssl_target}' platform")

# The OpenSSL Configure is a perl script, so run it explicitly with perl.
set(_easyssl_openssl_configure_cmd
    ${CMAKE_COMMAND}
    -E
    env
)

foreach(_env_item ${_easyssl_openssl_env})
    list(APPEND _easyssl_openssl_configure_cmd ${_env_item})
endforeach()

list(APPEND _easyssl_openssl_configure_cmd
    perl
    ${EASYSSL_OPENSSL_DIR}/source/Configure
    ${_easyssl_openssl_target}
    ${_easyssl_openssl_options}
    --prefix=${EASYSSL_OPENSSL_INSTALL_DIR}
    --openssldir=${EASYSSL_OPENSSL_INSTALL_DIR}
)

ExternalProject_Add(easyssl_openssl
    PREFIX ${EASYSSL_OPENSSL_DIR}
    SOURCE_DIR ${EASYSSL_OPENSSL_DIR}/source
    BINARY_DIR ${EASYSSL_OPENSSL_DIR}/build
    GIT_REPOSITORY "https://github.com/openssl/openssl.git"
    GIT_TAG ${EASYSSL_OPENSSL_TAG}
    GIT_SHALLOW TRUE
    GIT_PROGRESS TRUE
    UPDATE_COMMAND ""
    CONFIGURE_COMMAND ${_easyssl_openssl_configure_cmd}
    BUILD_COMMAND make -j build_libs
    INSTALL_COMMAND make install_sw
    TEST_COMMAND ""
)

# The imported targets of the built OpenSSL libraries. The library files
# are created by the easyssl_openssl ExternalProject target during the
# build, so the imported targets only need the final file locations.
file(MAKE_DIRECTORY "${EASYSSL_OPENSSL_INSTALL_DIR}/include")

add_library(easyssl_openssl_crypto STATIC IMPORTED GLOBAL)
set_target_properties(easyssl_openssl_crypto PROPERTIES
    IMPORTED_LOCATION "${EASYSSL_OPENSSL_INSTALL_DIR}/lib/libcrypto.a"
    INTERFACE_INCLUDE_DIRECTORIES "${EASYSSL_OPENSSL_INSTALL_DIR}/include"
)

add_library(easyssl_openssl_ssl STATIC IMPORTED GLOBAL)
set_target_properties(easyssl_openssl_ssl PROPERTIES
    IMPORTED_LOCATION "${EASYSSL_OPENSSL_INSTALL_DIR}/lib/libssl.a"
    INTERFACE_INCLUDE_DIRECTORIES "${EASYSSL_OPENSSL_INSTALL_DIR}/include"
    INTERFACE_LINK_LIBRARIES "easyssl_openssl_crypto"
)
