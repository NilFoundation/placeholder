#---------------------------------------------------------------------------#
# Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
# Copyright (c) 2024 Iosif (x-mass) <x-mass@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

cmake_minimum_required(VERSION 3.22 FATAL_ERROR)

project(debug-tools)

if(DEFINED CMAKE_BUILD_TYPE AND ${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -ggdb")
    set(BOOST_FORCEINLINE "OFF") # improves debugging traces
endif()

find_package(CM REQUIRED)
include(CMConfig)
include(CMDeploy)
include(CMSetupVersion)

cm_project(debug-tools WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES CXX)

# This is useful due to some build systems (Ninja in particular) are piping
# compiler output and compiler switches it's output to plain text
option (FORCE_COLORED_OUTPUT "Always produce ANSI-colored output (GNU/Clang only)." FALSE)
if (${FORCE_COLORED_OUTPUT})
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
       add_compile_options (-fdiagnostics-color=always)
    elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
       add_compile_options (-fcolor-diagnostics)
    endif ()
endif ()

# The file compile_commands.json is generated in build directory, so LSP could
# pick it up and guess all include paths, defines and other stuff.
# If Nix is used, LSP could not guess the locations of implicit include
# directories, so we need to include them explicitly.
if(CMAKE_EXPORT_COMPILE_COMMANDS)
  set(CMAKE_CXX_STANDARD_INCLUDE_DIRECTORIES
      ${CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES})
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

find_package(Boost REQUIRED COMPONENTS filesystem log program_options)

# Read version from VERSION file
set(VERSION_FILE "${CMAKE_CURRENT_LIST_DIR}/VERSION")
file(READ ${VERSION_FILE} DEBUG_TOOLS_VERSION)
string(STRIP ${DEBUG_TOOLS_VERSION} DEBUG_TOOLS_VERSION)
# Remove leading 'v' from tag
string(REGEX REPLACE "^v" "" DEBUG_TOOLS_VERSION ${DEBUG_TOOLS_VERSION})
if(NOT DEBUG_TOOLS_VERSION)
    message(FATAL_ERROR
            "Unable to retrive version from git or ${VERSION_FILE} file.")
endif()

# Split numbers
string(REPLACE "-" "." DEBUG_TOOLS_VERSION_LIST ${DEBUG_TOOLS_VERSION})
string(REPLACE "." ";" DEBUG_TOOLS_VERSION_LIST ${DEBUG_TOOLS_VERSION_LIST})

list(LENGTH DEBUG_TOOLS_VERSION_LIST VERSION_LIST_LENGHT)

list(GET DEBUG_TOOLS_VERSION_LIST 0 DEBUG_TOOLS_VERSION_MAJOR)
list(GET DEBUG_TOOLS_VERSION_LIST 1 DEBUG_TOOLS_VERSION_MINOR)
list(GET DEBUG_TOOLS_VERSION_LIST 2 DEBUG_TOOLS_VERSION_PATCH)
if(VERSION_LIST_LENGHT GREATER 3)
    list(GET DEBUG_TOOLS_VERSION_LIST 3 DEBUG_TOOLS_VERSION_INCREMENT)
endif()

set(CPACK_GENERATOR DEB)
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "=nil; Foundation")

set(CPACK_PACKAGE_VERSION "${DEBUG_TOOLS_VERSION_MAJOR}.${DEBUG_TOOLS_VERSION_MINOR}.${DEBUG_TOOLS_VERSION_PATCH}")
if(DEBUG_TOOLS_VERSION_INCREMENT)
    string(APPEND CPACK_PACKAGE_VERSION "-${DEBUG_TOOLS_VERSION_INCREMENT}")
endif()

set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/bin/circgen")
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/bin/excalibur")

include(CPack)

# INSTALL

set(CONFIG_PATH ${CMAKE_INSTALL_LIBDIR}/cmake/debug-tools)
set(TARGET_NAMESPACE crypto3::)
install(EXPORT debug-toolsTargets NAMESPACE ${TARGET_NAMESPACE} DESTINATION ${CONFIG_PATH})

include(CMakePackageConfigHelpers)
configure_package_config_file(
    cmake/Config.cmake.in
    debug-tools-config.cmake
    INSTALL_DESTINATION ${CONFIG_PATH}
)

install(
    FILES
    ${CMAKE_CURRENT_BINARY_DIR}/debug-tools-config.cmake
    DESTINATION ${CONFIG_PATH}
)
