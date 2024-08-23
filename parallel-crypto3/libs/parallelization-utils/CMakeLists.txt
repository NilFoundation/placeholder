cmake_minimum_required(VERSION 2.8.12)

cmake_policy(SET CMP0025 NEW)
cmake_policy(SET CMP0028 NEW)
cmake_policy(SET CMP0042 NEW)
cmake_policy(SET CMP0048 NEW)
cmake_policy(SET CMP0057 NEW)
cmake_policy(SET CMP0076 NEW)

include(CMConfig)
include(CMSetupVersion)
include(CMTest)

if(NOT CMAKE_WORKSPACE_NAME OR NOT ("${CMAKE_WORKSPACE_NAME}" STREQUAL "actor"))
    cm_workspace(actor)
endif()

macro(cm_find_package NAME)
    foreach(ITERATOR ${CMAKE_WORKSPACE_LIST})
        if(NOT "${NAME}" MATCHES "^${ITERATOR}_.*$" AND NOT "${NAME}" STREQUAL CM)
            find_package(${ARGV})
        else()
            set(${ARGV0}_FOUND ON CACHE BOOL "")
        endif()
    endforeach()
endmacro()

cm_project(core WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES C CXX)

if(NOT Boost_FOUND AND NOT CMAKE_CROSSCOMPILING)
    cm_find_package(Boost)
endif()

cm_find_package(CM)
include(CMDeploy)
include(FindPkgConfig)

option(BUILD_WITH_CCACHE "Build with ccache usage" TRUE)

if(UNIX AND BUILD_WITH_CCACHE)
    find_program(CCACHE_FOUND ccache)
    if(CCACHE_FOUND)
        set(CMAKE_CXX_COMPILER_LAUNCHER "ccache")
    endif(CCACHE_FOUND)
endif()

list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS)

list(APPEND ${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES)

list(APPEND ${CURRENT_PROJECT_NAME}_HEADERS ${${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS})

list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES ${${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES})

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                      EXPORT_NAME ${CURRENT_PROJECT_NAME})

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                           $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>

                           $<$<BOOL:${Boost_FOUND}>:${Boost_INCLUDE_DIRS}>)

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                      ${Boost_LIBRARIES})

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)


cm_add_test_subdirectory(test)
