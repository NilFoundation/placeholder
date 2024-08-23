include(CMConfig)
include(CMSetupVersion)

if(NOT CMAKE_WORKSPACE_NAME OR NOT ("${CMAKE_WORKSPACE_NAME}" STREQUAL "actor"))
    cm_workspace(actor)
endif()

option(ZK_PLACEHOLDER_PROFILING_ENABLED "Build with placeholder profiling" FALSE)
option(ZK_PLACEHOLDER_DEBUG_ENABLED "Build with placeholder testing inside" FALSE)

if(ZK_PLACEHOLDER_PROFILING)
    add_definitions(-DZK_PLACEHOLDER_PROFILING_ENABLED)
endif()

if(ZK_PLACEHOLDER_DEBUG)
    add_definitions(-DZK_PLACEHOLDER_DEBUG_ENABLED)
endif()

cm_project(zk WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES C CXX)

if(NOT Boost_FOUND AND NOT CMAKE_CROSSCOMPILING)
    find_package(Boost)
endif()

include(CMDeploy)
include(FindPkgConfig)

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                      EXPORT_NAME ${CURRENT_PROJECT_NAME})

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                           $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>

                           $<$<BOOL:${Boost_FOUND}>:${Boost_INCLUDE_DIRS}>)

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE

                      ${Boost_LIBRARIES}

                      ${CMAKE_WORKSPACE_NAME}::containers
                      ${CMAKE_WORKSPACE_NAME}::core
                      ${CMAKE_WORKSPACE_NAME}::math

                      crypto3::algebra
                      crypto3::block
                      crypto3::hash
                      crypto3::multiprecision)

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

include(CMTest)
cm_add_test_subdirectory(test)
