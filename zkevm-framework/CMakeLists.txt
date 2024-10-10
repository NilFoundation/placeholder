cmake_minimum_required(VERSION 3.27)

project(zkEVM-framework)

# Add json helpers to module path
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/libs/json_helpers/cmake ${CMAKE_MODULE_PATH})

option(BUILD_DOCS "Build documentation" FALSE)
option(ENABLE_TESTS "Enable tests" FALSE)

if(DEFINED CMAKE_BUILD_TYPE AND ${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -ggdb")
    set(BOOST_FORCEINLINE "OFF") # improves debugging traces
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
