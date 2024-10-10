#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

cmake_minimum_required(VERSION 3.21)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

find_package(CM REQUIRED)
include(CMConfig)
include(CMSetupVersion)
cm_workspace(crypto3)
cm_setup_version(VERSION 0.3.0 PREFIX ${CMAKE_WORKSPACE_NAME})

option(BUILD_SHARED_LIBS "Build shared library" FALSE) # TODO: it makes no sense for header-only lib, remove
option(Boost_USE_STATIC_LIBS "Use static libraries for Boost" OFF)
option(CMAKE_ENABLE_TESTS "Enable tests" FALSE) # used by CMTest module
option(BUILD_BENCH_TESTS "Build performance benchmark tests" FALSE)
option(BUILD_DOCS "Build with configuring Doxygen documentation compiler" FALSE)
option(SANITIZE "Build sanitizers" FALSE)

if(DEFINED CMAKE_BUILD_TYPE AND ${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -ggdb")
    set(BOOST_FORCEINLINE "OFF") # improves debugging traces
endif()

if(${SANITIZE})
  add_compile_options(-fsanitize=undefined,address,leak)
  add_link_options(-fsanitize=undefined,address,leak)
endif()

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

set(BUILD_WITH_TARGET_ARCHITECTURE "" CACHE STRING "Target build architecture") # TODO: check if we can do cross-compilation
set(DOXYGEN_OUTPUT_DIR "${CMAKE_CURRENT_LIST_DIR}/docs" CACHE STRING "Specify doxygen output directory")

include(TargetArchitecture)

if(BUILD_WITH_TARGET_ARCHITECTURE)
    set(CMAKE_TARGET_ARCHITECTURE ${BUILD_WITH_TARGET_ARCHITECTURE})
else()
    target_architecture(CMAKE_TARGET_ARCHITECTURE)
endif()

find_package(Boost REQUIRED COMPONENTS container random filesystem log log_setup program_options thread system unit_test_framework timer)

add_subdirectories("${CMAKE_CURRENT_LIST_DIR}/libs/")
add_subdirectories("${CMAKE_CURRENT_LIST_DIR}/libs/marshalling/")

add_library(${CMAKE_WORKSPACE_NAME}_all INTERFACE)
add_library(${CMAKE_WORKSPACE_NAME}::all ALIAS ${CMAKE_WORKSPACE_NAME}_all)
target_link_libraries(${CMAKE_WORKSPACE_NAME}_all INTERFACE
    crypto3::algebra
    crypto3::block
    crypto3::blueprint
    crypto3::transpiler
    crypto3::codec
    crypto3::containers
    crypto3::hash
    crypto3::marshalling-algebra
    crypto3::marshalling-core
    crypto3::marshalling-multiprecision
    crypto3::marshalling-zk
    crypto3::math
    crypto3::multiprecision
    crypto3::passhash
    crypto3::pubkey
    crypto3::random
    crypto3::stream
    crypto3::threshold
    crypto3::zk)

add_library(${CMAKE_WORKSPACE_NAME}_common INTERFACE)
add_library(${CMAKE_WORKSPACE_NAME}::common ALIAS ${CMAKE_WORKSPACE_NAME}_common)
target_link_libraries(${CMAKE_WORKSPACE_NAME}_common INTERFACE
    crypto3::algebra
    crypto3::benchmark_tools
    crypto3::block
    crypto3::blueprint
    crypto3::transpiler
    crypto3::codec
    crypto3::hash
    crypto3::marshalling-algebra
    crypto3::marshalling-core
    crypto3::marshalling-multiprecision
    crypto3::marshalling-zk
    crypto3::multiprecision
    crypto3::passhash
    crypto3::pubkey
    crypto3::random
    crypto3::stream
    crypto3::threshold)

if(BUILD_BENCH_TESTS)
    add_subdirectory(benchmarks)
endif()

configure_file(${CMAKE_CURRENT_LIST_DIR}/docs/doxygen/${CMAKE_WORKSPACE_NAME}.doxyfile.in
        ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_WORKSPACE_NAME}.doxyfile @ONLY)

# Configure package file to be able to import crypto3 headers
# TODO: remove it after resolving cyclical dependencies in crypto3 modules
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)
set(CONFIG_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/crypto3)

configure_package_config_file(
        cmake/Config.cmake.in
        crypto3Config.cmake
        INSTALL_DESTINATION ${CONFIG_DIR}
)

install(
        FILES
        ${CMAKE_CURRENT_BINARY_DIR}/crypto3Config.cmake
        DESTINATION ${CONFIG_DIR}
)
