#
# Copyright (C) 2020-2023 QuasarApp.
# Distributed under the GPLv3 software license, see the accompanying
# Everyone is permitted to copy and distribute verbatim copies
# of this license document, but changing it is not allowed.
#

cmake_minimum_required(VERSION 3.18)
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

if (ANDROID OR IOS)
    set(BUILD_SHARED_LIBS ON)
endif()

if (NOT QT_VERSION_MAJOR)
    find_package(QT NAMES Qt6 Qt5 COMPONENTS Core Test QUIET)
endif()
find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Core Test QUIET)

include(submodules/CMake/QuasarApp.cmake)

updateGitVars()
set(easyssl_VERSION "0.${GIT_COMMIT_COUNT}.${GIT_COMMIT_HASH}")
set(easyssl_PACKAGE_ID "quasarapp.core.easyssl")

option(easyssl_TESTS "This option disables or enables tests of the ${PROJECT_NAME} project"  ON)
option(easyssl_EXAMPLE "This option disables or enables example app of the ${PROJECT_NAME} project" ON)

if (ANDROID OR IOS OR NOT QT_VERSION_MAJOR OR QA_WASM32)
    set(easyssl_TESTS OFF CACHE BOOL "This option force disbled for ANDROID IOS QA_WASM32 and Not Qt projects" FORCE)
endif()

if (NOT QT_VERSION_MAJOR)
    set(easyssl_EXAMPLE OFF CACHE BOOL "This option force disbled for Not Qt projects" FORCE)
endif()

make_directory(Distro)

initAll()

add_subdirectory(src/Library)

if (DEFINED easyssl_EXAMPLE)
    add_subdirectory(src/Example)
endif()

if (easyssl_TESTS)
    add_subdirectory(tests)
else()
    message("The ${PROJECT_NAME} tests is disabled.")
endif()


addDoc(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/doxygen.conf)
addDeployFromCustomFile("easyssl" "${CMAKE_CURRENT_SOURCE_DIR}/Deploy/easyssl.json")
