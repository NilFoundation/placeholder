cmake_minimum_required(VERSION 2.8.12)

cmake_policy(SET CMP0028 NEW)
cmake_policy(SET CMP0063 NEW)

option(BUILD_ASSIGNER_TESTS "Build unit tests" FALSE)

if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(CMAKE_CXX_FLAGS "-ggdb -O0")
endif()

set(evmone_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/evmone/baseline.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/evmone/baseline_instruction_table.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/evmone/eof.cpp
)

add_library(${PROJECT_NAME} STATIC ${evmone_sources})

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_20)

find_package(crypto3 REQUIRED)

target_include_directories(${PROJECT_NAME} PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                           $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/evmc>
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/evmone>)

target_link_libraries(${PROJECT_NAME}
                      PUBLIC intx::intx crypto3::all ethash::keccak)

set_target_properties(
    ${PROJECT_NAME}
    PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_SOVERSION}
)

# Install assigner headers
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
# Install library
install(TARGETS ${PROJECT_NAME} EXPORT assignerTargets DESTINATION ${CMAKE_INSTALL_LIBDIR})

# Install evmone headers
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/evmone/execution_state.hpp
              ${CMAKE_CURRENT_SOURCE_DIR}/evmone/baseline_instruction_table.hpp
              ${CMAKE_CURRENT_SOURCE_DIR}/evmone/instructions.hpp
              ${CMAKE_CURRENT_SOURCE_DIR}/evmone/instructions_traits.hpp
              ${CMAKE_CURRENT_SOURCE_DIR}/evmone/instructions_xmacro.hpp
              ${CMAKE_CURRENT_SOURCE_DIR}/evmone/baseline.hpp
              ${CMAKE_CURRENT_SOURCE_DIR}/evmone/eof.hpp
              ${CMAKE_CURRENT_SOURCE_DIR}/evmone/instructions_opcodes.hpp
              ${CMAKE_CURRENT_SOURCE_DIR}/evmc/evmc.h
              ${CMAKE_CURRENT_SOURCE_DIR}/evmc/evmc.hpp
              ${CMAKE_CURRENT_SOURCE_DIR}/evmc/filter_iterator.hpp
              ${CMAKE_CURRENT_SOURCE_DIR}/evmc/helpers.h
              ${CMAKE_CURRENT_SOURCE_DIR}/evmc/hex.hpp
              ${CMAKE_CURRENT_SOURCE_DIR}/evmc/utils.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
if(BUILD_ASSIGNER_TESTS)
    add_subdirectory(test)
endif()
