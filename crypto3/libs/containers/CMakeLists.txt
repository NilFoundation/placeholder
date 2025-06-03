#---------------------------------------------------------------------------//
#  MIT License
#
#  Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
#  Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in all
#  copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#  SOFTWARE.
#---------------------------------------------------------------------------//

include(CMConfig)
include(CMSetupVersion)

include(CMSetupVersion)

if (NOT Boost_FOUND AND NOT CMAKE_CROSSCOMPILING)
    find_package(Boost COMPONENTS REQUIRED filesystem)
endif ()

cm_project(containers WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME})

option(BUILD_DOXYGEN_DOCS "Build with configuring Doxygen documentation compiler" TRUE)

set(DOXYGEN_OUTPUT_DIR "${CMAKE_CURRENT_LIST_DIR}/docs" CACHE STRING "Specify doxygen output directory")

list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
        )

list(APPEND ${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES)

list(APPEND ${CURRENT_PROJECT_NAME}_HEADERS
        ${${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS}
        ${${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES})

list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
        ${${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES})

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)
add_library(${CMAKE_WORKSPACE_NAME}::${CURRENT_PROJECT_NAME} ALIAS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
        EXPORT_NAME ${CURRENT_PROJECT_NAME})

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE

        crypto3::core
        crypto3::algebra
        crypto3::hash)

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
        "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

        ${Boost_INCLUDE_DIRS})

add_tests(test)

if (BUILD_EXAMPLES)
    add_subdirectory(example)
endif ()

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
