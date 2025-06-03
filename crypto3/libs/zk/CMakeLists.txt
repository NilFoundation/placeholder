include(CMConfig)
include(CMSetupVersion)

option(PROFILING_ENABLED "Build with placeholder profiling" FALSE)
option(ZK_PLACEHOLDER_DEBUG_ENABLED "Build with placeholder testing inside" FALSE)

if(PROFILING_ENABLED)
    add_definitions(-DPROFILING_ENABLED)
endif()

if(ZK_PLACEHOLDER_DEBUG_ENABLED)
    add_definitions(-DZK_PLACEHOLDER_DEBUG_ENABLED)
endif()

cm_project(zk WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES C CXX)

include(FindPkgConfig)

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)
add_library(${CMAKE_WORKSPACE_NAME}::${CURRENT_PROJECT_NAME} ALIAS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                      EXPORT_NAME ${CURRENT_PROJECT_NAME})

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                           $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>

                           $<$<BOOL:${Boost_FOUND}>:${Boost_INCLUDE_DIRS}>)

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE

                      Boost::container
                      Boost::log

                      # Containers and math implementation could be replaced with namespace change
                      crypto3::containers
                      crypto3::math
                      crypto3::core
                      crypto3::algebra
                      crypto3::hash
                      crypto3::multiprecision
                      crypto3::marshalling-zk

                      # crypto3::benchmark_tools
)

include(CMTest)
add_tests(test)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
