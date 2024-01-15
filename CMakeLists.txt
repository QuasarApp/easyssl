#
# Copyright (C) 2020-2024 QuasarApp.
# Distributed under the GPLv3 software license, see the accompanying
# Everyone is permitted to copy and distribute verbatim copies
# of this license document, but changing it is not allowed.
#

cmake_minimum_required(VERSION 3.19)
project(easyssl LANGUAGES CXX)
if(TARGET ${PROJECT_NAME})
    message("The ${PROJECT_NAME} arledy included in main Project")
    return()
endif()

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (ANDROID)
    set(BUILD_SHARED_LIBS ON)
endif()

if (NOT QT_VERSION_MAJOR)
    find_package(QT NAMES Qt6 Qt5 COMPONENTS Core Network Test REQUIRED)
endif()
find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Core Network Test REQUIRED)

include(submodules/CMake/QuasarApp.cmake)

updateGitVars()
set(EASYSSL_VERSION "0.${GIT_COMMIT_COUNT}.${GIT_COMMIT_HASH}")
set(EASYSSL_PACKAGE_ID "quasarapp.core.easyssl")

option(EASYSSL_TESTS "This option disables or enables tests of the ${PROJECT_NAME} project"  ON)
option(EASYSSL_STATIC_SSL "This option enable or disabled static link ssl libraryes" OFF)
option(BUILD_WITH_OPENSSL "This option enable or disabled build thirdparty libraryes with easyssl library (for example openssl)" OFF)

if (BUILD_WITH_OPENSSL)
    if (QA_WASM32 OR WIN32)
        critical("The BUILD_WITH_OPENSSL not supports the Windows and WASM platforms")
    endif()
endif()

if (ANDROID OR IOS OR NOT QT_VERSION_MAJOR OR QA_WASM32)
    set(EASYSSL_TESTS OFF CACHE BOOL "This option force disbled for ANDROID IOS QA_WASM32 and Not Qt projects" FORCE)
endif()

make_directory(Distro)

initAll()

add_subdirectory(src/lib)

if (EASYSSL_TESTS)
    add_subdirectory(tests)
else()
    message("The ${PROJECT_NAME} tests is disabled.")
endif()

configure_file_in(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/doxygen.conf)
addDoc(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/doxygen.conf)
addDeployFromCustomFile("easyssl" "${CMAKE_CURRENT_SOURCE_DIR}/Deploy/easyssl.json")
