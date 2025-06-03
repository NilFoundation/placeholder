#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>")

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
    crypto3::random
    crypto3::benchmark_tools
    crypto3::marshalling-zk
    crypto3::core
    Boost::unit_test_framework
    Boost::log
    )
set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES CXX_STANDARD 23)
target_precompile_headers(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} REUSE_FROM crypto3_precompiled_headers)

if(PROFILING_ENABLED)
    add_definitions(-DPROFILING_ENABLED)
endif()

macro(define_zk_test test)
    get_filename_component(name ${test} NAME)
    string(REPLACE "/" "_" full_test_name ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_${test}_test)

    cm_test(NAME ${full_test_name} SOURCES ${test}.cpp)

    target_include_directories(${full_test_name} PRIVATE
                                "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                                "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../../test_tools/include>"
                                "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(${full_test_name} PROPERTIES CXX_STANDARD 23)

    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${full_test_name} PRIVATE "-fconstexpr-steps=2147483647")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${full_test_name} PRIVATE "-fconstexpr-ops-limit=4294967295")
    endif()

    target_precompile_headers(${full_test_name} REUSE_FROM crypto3_precompiled_headers)
endmacro()

set(TESTS_NAMES
    "commitment/lpc"
    "commitment/fri"
    "commitment/kzg"
    "commitment/fold_polynomial"
    "commitment/proof_of_work"

    "math/expression"
    "math/dag_expression_evaluator"

    "systems/plonk/placeholder/placeholder_circuits"
    "systems/plonk/placeholder/placeholder_circuits_dFRI"
    "systems/plonk/placeholder/placeholder_goldilocks"
    # TODO(ioxid): Mersenne31 is unsupported for now.
    # "systems/plonk/placeholder/placeholder_mersenne31"
    "systems/plonk/placeholder/placeholder_koalabear"
    "systems/plonk/placeholder/placeholder_babybear"
    "systems/plonk/placeholder/placeholder_lookup_argument"
    "systems/plonk/placeholder/placeholder_gate_argument"
    "systems/plonk/placeholder/placeholder_permutation_argument"
    "systems/plonk/placeholder/placeholder_kzg"
    "systems/plonk/placeholder/placeholder_hashes"
    "systems/plonk/placeholder/placeholder_curves"
    "systems/plonk/placeholder/placeholder_quotient_polynomial_chunks"

    "transcript/transcript"

    "systems/plonk/plonk_constraint")

foreach(TEST_NAME ${TESTS_NAMES})
    define_zk_test(${TEST_NAME})
endforeach()


