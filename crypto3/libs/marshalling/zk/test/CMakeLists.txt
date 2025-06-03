#---------------------------------------------------------------------------#
# Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        Boost::unit_test_framework

        crypto3::multiprecision
        crypto3::algebra
        crypto3::zk
        crypto3::hash
        crypto3::random
        crypto3::math
        crypto3::marshalling-multiprecision
        crypto3::marshalling-algebra
        crypto3::marshalling-core
        )

macro(define_marshalling_test test)

    get_filename_component(name ${test} NAME)

    set(full_test_name marshalling_zk_${name}_test)
    cm_test(NAME ${full_test_name} SOURCES ${test}.cpp)

    target_include_directories(marshalling_zk_${name}_test PRIVATE
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../../../test_tools/include>"
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
            "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

            ${Boost_INCLUDE_DIRS})

    set_target_properties(marshalling_zk_${name}_test PROPERTIES
            CXX_STANDARD 23
            CXX_STANDARD_REQUIRED TRUE)

    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${full_test_name} PRIVATE "-fconstexpr-steps=2147483647")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${full_test_name} PRIVATE "-fconstexpr-ops-limit=4294967295")
    endif()
    target_precompile_headers(${full_test_name} REUSE_FROM crypto3_precompiled_headers)
endmacro()

set(TESTS_NAMES
        "merkle_proof"
        "merkle_tree"
        "accumulation_vector"
        "sparse_vector"
        "kzg_commitment"
        "fri_commitment"
        "lpc_commitment"
        "polys_evaluator"
        "placeholder_proof"
        "placeholder_common_data"
        "placeholder_preprocessed_public_data"
        "plonk_gates"
        "plonk_constraint_system"
        "plonk_assignment_table"
        )

foreach(TEST_NAME ${TESTS_NAMES})
    define_marshalling_test(${TEST_NAME})
endforeach()
