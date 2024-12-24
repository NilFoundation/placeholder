#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

cmake_minimum_required(VERSION 3.22 FATAL_ERROR)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

find_package(CM REQUIRED)
include(CMConfig)
include(CMSetupVersion)
cm_workspace(crypto3)
cm_setup_version(VERSION 0.3.0 PREFIX ${CMAKE_WORKSPACE_NAME})

option(BUILD_TESTS "Enable tests" TRUE) # used by CMTest module; If set to false, tests are removed from crypto3::all target. User still can build individual ones.
option(BUILD_CRYPTO3_TESTS "Enable tests" FALSE)
option(BUILD_CRYPTO3_BENCH_TESTS "Build performance benchmark tests" FALSE)
option(BUILD_DOCS "Build with configuring Doxygen documentation compiler" FALSE)

# The file compile_commands.json is generated in build directory, so LSP could
# pick it up and guess all include paths, defines and other stuff.
# If Nix is used, LSP could not guess the locations of implicit include
# directories, so we need to include them explicitly.
if(CMAKE_EXPORT_COMPILE_COMMANDS)
  set(CMAKE_CXX_STANDARD_INCLUDE_DIRECTORIES 
      ${CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES})
endif()

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  add_compile_options (-fdiagnostics-color=always)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  add_compile_options (-fcolor-diagnostics)
endif ()

set(BUILD_WITH_TARGET_ARCHITECTURE "" CACHE STRING "Target build architecture") # TODO: check if we can do cross-compilation
set(DOXYGEN_OUTPUT_DIR "${CMAKE_CURRENT_LIST_DIR}/docs" CACHE STRING "Specify doxygen output directory")

include(TargetArchitecture)

if(BUILD_WITH_TARGET_ARCHITECTURE)
    set(CMAKE_TARGET_ARCHITECTURE ${BUILD_WITH_TARGET_ARCHITECTURE})
else()
    target_architecture(CMAKE_TARGET_ARCHITECTURE)
endif()

find_package(Boost REQUIRED COMPONENTS container random filesystem log log_setup program_options thread system unit_test_framework timer)

function(add_tests)
    if (${BUILD_CRYPTO3_TESTS})
        add_subdirectory(test)
    endif ()
endfunction(add_tests)

add_subdirectories("${CMAKE_CURRENT_LIST_DIR}/libs/")
add_subdirectories("${CMAKE_CURRENT_LIST_DIR}/libs/marshalling/")

add_library(${CMAKE_WORKSPACE_NAME}_all INTERFACE)
add_library(${CMAKE_WORKSPACE_NAME}::all ALIAS ${CMAKE_WORKSPACE_NAME}_all)
target_link_libraries(${CMAKE_WORKSPACE_NAME}_all INTERFACE
    crypto3::algebra
    crypto3::blueprint
    crypto3::transpiler
    crypto3::containers
    crypto3::hash
    crypto3::marshalling-algebra
    crypto3::marshalling-core
    crypto3::marshalling-multiprecision
    crypto3::marshalling-zk
    crypto3::math
    crypto3::multiprecision
    crypto3::random
    crypto3::zk)

add_library(${CMAKE_WORKSPACE_NAME}_common INTERFACE)
add_library(${CMAKE_WORKSPACE_NAME}::common ALIAS ${CMAKE_WORKSPACE_NAME}_common)
target_link_libraries(${CMAKE_WORKSPACE_NAME}_common INTERFACE
    crypto3::algebra
    crypto3::benchmark_tools
    crypto3::blueprint
    crypto3::transpiler
    crypto3::hash
    crypto3::marshalling-algebra
    crypto3::marshalling-core
    crypto3::marshalling-multiprecision
    crypto3::marshalling-zk
    crypto3::multiprecision
    crypto3::random
)

if(BUILD_CRYPTO3_BENCH_TESTS)
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
