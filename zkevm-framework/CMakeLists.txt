cmake_minimum_required(VERSION 3.27)

project(zkEVM-framework)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})
# Add json helpers to module path
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/libs/json_helpers/cmake ${CMAKE_MODULE_PATH})
include(GNUInstallDirs)

option(BUILD_DOCS "Build documentation" FALSE)
option(ENABLE_TESTS "Enable tests" FALSE)

if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(CMAKE_CXX_FLAGS "-ggdb -O0")
endif()

add_subdirectory(libs)
add_subdirectory(bin)

if(BUILD_DOCS)
    find_package(Doxygen REQUIRED)
    doxygen_add_docs(docs COMMENT "Generating API documentation with Doxygen")
endif()

if(ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
