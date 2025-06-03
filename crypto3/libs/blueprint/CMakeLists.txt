include(CMConfig)
include(CMSetupVersion)

cm_project(blueprint WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES C CXX)

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)
add_library(${CMAKE_WORKSPACE_NAME}::${CURRENT_PROJECT_NAME} ALIAS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
        EXPORT_NAME ${CURRENT_PROJECT_NAME})

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../test_tools/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>)

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
        Boost::container
        Boost::log_setup
        Boost::log
        crypto3::algebra
        crypto3::zk
        crypto3::random
        crypto3::hash
)
include(CMTest)
add_tests(test)

if(BUILD_EXAMPLES)
    add_subdirectory(example)
endif()

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
