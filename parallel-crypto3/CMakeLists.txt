cmake_minimum_required(VERSION 3.22 FATAL_ERROR)
project(parallel-crypto3)

find_package(CM REQUIRED)
include(CMConfig)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# The file compile_commands.json is generated in build directory, so LSP could
# pick it up and guess all include paths, defines and other stuff.
# If Nix is used, LSP could not guess the locations of implicit include
# directories, so we need to include them explicitly.
if(CMAKE_EXPORT_COMPILE_COMMANDS)
  set(CMAKE_CXX_STANDARD_INCLUDE_DIRECTORIES
      ${CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES})
endif()

# TODO: check what is actually required here
include(CMSetupVersion)

# TODO: beutify entire cmake tree of parallel crypto3 modules the same way we did in origin crypto3
find_package(Boost REQUIRED COMPONENTS filesystem log program_options thread random unit_test_framework container)

add_subdirectory(libs/parallelization-utils)
add_subdirectory(libs/parallel-containers)
add_subdirectory(libs/parallel-math)
add_subdirectory(libs/parallel-zk)

add_library(${PROJECT_NAME}_all INTERFACE)
add_library(${PROJECT_NAME}::all ALIAS ${PROJECT_NAME}_all)
target_link_libraries(${PROJECT_NAME}_all INTERFACE
    actor::containers
    actor::math
    actor::zk
    actor::core)

# Configure package file to be able to import headers
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)
set(CONFIG_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/parallel-crypto3)

configure_package_config_file(
        cmake/Config.cmake.in
        parallel-crypto3Config.cmake
        INSTALL_DESTINATION ${CONFIG_DIR}
)

install(
        FILES
        ${CMAKE_CURRENT_BINARY_DIR}/parallel-crypto3Config.cmake
        DESTINATION ${CONFIG_DIR}
)
