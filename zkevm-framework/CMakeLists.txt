cmake_minimum_required(VERSION 3.27)

project(zkEVM-framework)

# Add json helpers to module path
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/libs/json_helpers/cmake ${CMAKE_MODULE_PATH})

option(BUILD_DOCS "Build documentation" FALSE)
option(ENABLE_TESTS "Enable tests" FALSE)

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
