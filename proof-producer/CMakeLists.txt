#---------------------------------------------------------------------------#
# Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
# Copyright (c) 2024 Iosif (x-mass) <x-mass@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

cmake_minimum_required(VERSION 3.22 FATAL_ERROR)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")

if(DEFINED CMAKE_BUILD_TYPE AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(ZK_PLACEHOLDER_DEBUG_ENABLED TRUE)
endif()

find_package(CM REQUIRED)
include(CMConfig)
include(CMDeploy)
include(CMSetupVersion)

option(PROOF_PRODUCER_STATIC_BINARIES "Link proof-producer binaries statically" OFF)

if(PROOF_PRODUCER_STATIC_BINARIES)
    set(BUILD_SHARED_LIBS OFF)
    set(Boost_USE_STATIC_LIBS ON)
else()
    set(BUILD_SHARED_LIBS OFF)  # TODO: fix invalid-pch issue with precompiled headers to build shared libraries
    set(Boost_USE_STATIC_LIBS OFF)
endif()

cm_project(proof-producer WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES CXX)

# The file compile_commands.json is generated in build directory, so LSP could
# pick it up and guess all include paths, defines and other stuff.
# If Nix is used, LSP could not guess the locations of implicit include
# directories, so we need to include them explicitly.
if(CMAKE_EXPORT_COMPILE_COMMANDS)
  set(CMAKE_CXX_STANDARD_INCLUDE_DIRECTORIES
      ${CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES})
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

# TODO: move thread to actor-core
find_package(Boost REQUIRED COMPONENTS filesystem log program_options thread)
if(ENABLE_TESTS)
    find_package(Boost REQUIRED COMPONENTS unit_test_framework)
endif()

# Read version from VERSION file
set(VERSION_FILE "${CMAKE_CURRENT_LIST_DIR}/VERSION")
file(READ ${VERSION_FILE} PROOF_PRODUCER_VERSION)
string(STRIP ${PROOF_PRODUCER_VERSION} PROOF_PRODUCER_VERSION)
# Remove leading 'v' from tag
string(REGEX REPLACE "^v" "" PROOF_PRODUCER_VERSION ${PROOF_PRODUCER_VERSION})
if(NOT PROOF_PRODUCER_VERSION)
    message(FATAL_ERROR
            "Unable to retrive version from git or ${VERSION_FILE} file.")
endif()

# Split numbers
string(REPLACE "-" "." PROOF_PRODUCER_VERSION_LIST ${PROOF_PRODUCER_VERSION})
string(REPLACE "." ";" PROOF_PRODUCER_VERSION_LIST ${PROOF_PRODUCER_VERSION_LIST})

list(LENGTH PROOF_PRODUCER_VERSION_LIST VERSION_LIST_LENGHT)

list(GET PROOF_PRODUCER_VERSION_LIST 0 PROOF_PRODUCER_VERSION_MAJOR)
list(GET PROOF_PRODUCER_VERSION_LIST 1 PROOF_PRODUCER_VERSION_MINOR)
list(GET PROOF_PRODUCER_VERSION_LIST 2 PROOF_PRODUCER_VERSION_PATCH)
if(VERSION_LIST_LENGHT GREATER 3)
    list(GET PROOF_PRODUCER_VERSION_LIST 3 PROOF_PRODUCER_VERSION_INCREMENT)
endif()

set(CPACK_GENERATOR DEB)
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "=nil; Foundation")

set(CPACK_PACKAGE_VERSION "${PROOF_PRODUCER_VERSION_MAJOR}.${PROOF_PRODUCER_VERSION_MINOR}.${PROOF_PRODUCER_VERSION_PATCH}")
if(PROOF_PRODUCER_VERSION_INCREMENT)
    string(APPEND CPACK_PACKAGE_VERSION "-${PROOF_PRODUCER_VERSION_INCREMENT}")
endif()

set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/libs/output_artifacts")
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/libs/preset")
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/libs/assigner")
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/bin/proof-producer")

if (ENABLE_TESTS)
    enable_testing()
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/tests")
endif()
