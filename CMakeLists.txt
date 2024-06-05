cmake_minimum_required(VERSION 3.22 FATAL_ERROR)
project(parallel-crypto3)

list(APPEND CMAKE_MODULE_PATH
    "${CMAKE_CURRENT_LIST_DIR}/cmake/modules/share/modules/cmake")

# TODO: check what is actually required here
include(CMConfig)
include(CMDeploy)
include(CMSetupVersion)

# TODO: beutify entire cmake tree of parallel crypto3 modules the same way we did in origin crypto3
find_package(Boost REQUIRED COMPONENTS filesystem log program_options thread random unit_test_framework)
find_package(crypto3 REQUIRED)

# HACK: since there are no more crypto3::submodule targets, we have to ALIAS any used
#   target of such type to recently introduced crypto3::all target
# TODO: update dependencies in actor modules
add_library(crypto3::algebra ALIAS crypto3::all)
add_library(crypto3::block ALIAS crypto3::all)
add_library(crypto3::hash ALIAS crypto3::all)
add_library(crypto3::multiprecision ALIAS crypto3::all)
add_library(crypto3::random ALIAS crypto3::all)
add_library(marshalling::core ALIAS crypto3::all)
add_library(marshalling::crypto3_multiprecision ALIAS crypto3::all)
add_library(marshalling::crypto3_algebra ALIAS crypto3::all)
add_library(marshalling::crypto3_zk ALIAS crypto3::all)

add_subdirectory(libs/parallelization-utils)
add_subdirectory(libs/parallel-containers)
add_subdirectory(libs/parallel-math)
add_subdirectory(libs/parallel-zk)
