#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                       ${${CURRENT_PROJECT_NAME}_INTERFACE_LIBRARIES}
                       Boost::unit_test_framework)

set_target_properties(_cm_internal_tests-crypto3-hash-test PROPERTIES CXX_STANDARD 23)
target_precompile_headers(_cm_internal_tests-crypto3-hash-test REUSE_FROM crypto3_precompiled_headers)

macro(define_hash_test name)
    set(test_name "hash_${name}_test")

    cm_test(NAME ${test_name} SOURCES ${name}.cpp)

    target_include_directories(${test_name} PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(${test_name} PROPERTIES
                          CXX_STANDARD 23
                          CXX_STANDARD_REQUIRED TRUE)

    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${test_name} PRIVATE "-fconstexpr-steps=2147483647")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${test_name} PRIVATE "-fconstexpr-ops-limit=4294967295")
    endif()

    target_compile_options(${test_name} PRIVATE "-ftemplate-backtrace-limit=0")

    string(CONCAT TEST_DATA ${CMAKE_CURRENT_SOURCE_DIR} "/data/" "${name}" ".json")
    target_compile_definitions(${test_name} PRIVATE TEST_DATA="${TEST_DATA}")

    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${test_name} PRIVATE "-fconstexpr-steps=2147483647")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${test_name} PRIVATE "-fconstexpr-ops-limit=4294967295")
    endif()

    target_precompile_headers(${test_name} REUSE_FROM crypto3_precompiled_headers)
endmacro()

set(TESTS_NAMES
    "keccak"
    "pack"
    "sha2"
    "sha3"
    "static_digest"
    "poseidon"
    "hash_to_curve"
    "type_traits"
    )

foreach(TEST_NAME ${TESTS_NAMES})
    define_hash_test(${TEST_NAME})
endforeach()
