#
# Copyright (C) 2020-2025 QuasarApp.
# Distributed under the GPLv3 software license, see the accompanying
# Everyone is permitted to copy and distribute verbatim copies
# of this license document, but changing it is not allowed.
#

cmake_minimum_required(VERSION 3.19)

get_filename_component(CURRENT_PROJECT_DIR ${CMAKE_CURRENT_SOURCE_DIR} NAME)

set(CURRENT_PROJECT "${PROJECT_NAME}")
add_definitions(-DEASYSSL_LIBRARY)

file(GLOB_RECURSE SOURCE_CPP
    "src/*.cpp"
    "src/*.h"
)

if (${QT_VERSION_MAJOR})
    file(GLOB_RECURSE SOURCE_QRC
        "*.qrc"
    )

endif()

set(PUBLIC_INCUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/public")
set(PRIVATE_INCUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/private")


add_library(${CURRENT_PROJECT} ${SOURCE_CPP} ${SOURCE_QRC})

target_link_libraries(${CURRENT_PROJECT} PUBLIC Qt${QT_VERSION_MAJOR}::Network Qt${QT_VERSION_MAJOR}::Core )

if (BUILD_WITH_OPENSSL)

    # The OpenSSL libraries are built with the project (see the
    # cmake/BuildOpenSSL.cmake file). The easyssl target is linked
    # against the imported targets of the built OpenSSL libraries.
    message("Use the OpenSSL libraries that are built with the project")
    target_link_libraries(${CURRENT_PROJECT} PRIVATE easyssl_openssl_ssl easyssl_openssl_crypto)

    if (WIN32)
        # The OpenSSL mingw64 build needs these Windows system libraries.
        target_link_libraries(${CURRENT_PROJECT} PRIVATE ws2_32 gdi32 crypt32)
    endif()

else()

    if (EASYSSL_STATIC_SSL)
        set(OPENSSL_USE_STATIC_LIBS ON)
    endif()

    list(APPEND CMAKE_FIND_ROOT_PATH "$ENV{OPENSSL_ROOT_DIR}")
    find_package(OpenSSL 3.0 REQUIRED)

    if (EASYSSL_STATIC_SSL)

        message("Use static ssl")
        target_link_libraries(${CURRENT_PROJECT} PRIVATE ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
    else()

        message("Use shared ssl ")
        target_link_libraries(${CURRENT_PROJECT} PRIVATE OpenSSL::Crypto OpenSSL::SSL)

        if (ANDROID)
            set(OPENSSL_ROOT_PATH "$ENV{OPENSSL_ROOT_DIR}")

            set(ANDROID_EXTRA_LIBS
                ${OPENSSL_ROOT_PATH}/lib/libcrypto_android.so
                ${OPENSSL_ROOT_PATH}/lib/libssl_android.so
            CACHE INTERNAL "")

            message(ANDROID_EXTRA_LIBS = ${ANDROID_EXTRA_LIBS})
        endif()
    endif()

    message("Use the OpenSSL libraries: ${OPENSSL_LIBRARIES}")

endif()

target_include_directories(${CURRENT_PROJECT} PUBLIC ${PUBLIC_INCUDE_DIR})
target_include_directories(${CURRENT_PROJECT} PRIVATE ${PRIVATE_INCUDE_DIR})

set(LANGS ${CMAKE_CURRENT_SOURCE_DIR}/languages/en.ts)


prepareQM(${CURRENT_PROJECT} ${CMAKE_CURRENT_SOURCE_DIR} "${LANGS}")

set(QML_IMPORT_PATH ${QML_IMPORT_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/src" CACHE STRING "" FORCE)

set(global_file "${CMAKE_CURRENT_SOURCE_DIR}/src/public/easyssl/global.h")
configure_file("${global_file}.in" ${global_file} @ONLY)
