#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

cmake_minimum_required(VERSION 3.22 FATAL_ERROR)

find_package(CM REQUIRED)
include(CMConfig)
include(CMSetupVersion)

if(DEFINED CMAKE_BUILD_TYPE AND ${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -ggdb")
    set(BOOST_FORCEINLINE "OFF") # improves debugging traces
endif()

cm_project(transpiler WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES ASM C CXX)

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)
add_library(${CMAKE_WORKSPACE_NAME}::${CURRENT_PROJECT_NAME} ALIAS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
        EXPORT_NAME ${CURRENT_PROJECT_NAME})

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>)

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
        ${Boost_LIBRARIES})

include(CMTest)
cm_add_test_subdirectory(test)

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)
set(CONFIG_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/${CURRENT_PROJECT_NAME})

# Install transpiler headers
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
