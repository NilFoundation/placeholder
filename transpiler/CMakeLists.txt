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

if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(CMAKE_CXX_FLAGS "-ggdb -O0")
endif()

cm_workspace(crypto3)
cm_project(transpiler WORKSPACE_NAME crypto3 LANGUAGES ASM C CXX)

cm_setup_version(VERSION 0.1.0 PREFIX crypto3_transpiler)

find_package(crypto3 REQUIRED)

add_library(crypto3_transpiler INTERFACE)

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                      EXPORT_NAME ${CURRENT_PROJECT_NAME})


target_include_directories(crypto3_transpiler INTERFACE
                           "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                           "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                           ${Boost_INCLUDE_DIRS})

target_link_libraries(crypto3_transpiler INTERFACE
                      crypto3::all
                      ${Boost_LIBRARIES})

include(CMTest)
cm_add_test_subdirectory(test)

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)
set(CONFIG_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/crypto3_transpiler)

configure_package_config_file(
        cmake/Config.cmake.in
        crypto3_transpilerConfig.cmake
        INSTALL_DESTINATION ${CONFIG_DIR}
)

# Install generated cmake config
install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/crypto3_transpilerConfig.cmake
        DESTINATION ${CONFIG_DIR}
)

# Install transpiler headers
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
