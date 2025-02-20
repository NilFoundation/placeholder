#---------------------------------------------------------------------------#
# Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@gmail.com>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

option(ZK_PLACEHOLDER_PROFILING "Build with placeholder profiling" FALSE)
option(ZK_PLACEHOLDER_DEBUG "Build with placeholder debug output" FALSE)

if(ZK_PLACEHOLDER_PROFILING)
    add_definitions(-DZK_PLACEHOLDER_PROFILING_ENABLED)
endif()

if(ZK_PLACEHOLDER_DEBUG)
    add_definitions(-DZK_PLACEHOLDER_DEBUG_ENABLED)
endif()

option(BLUEPRINT_DEBUG "Build with blueprint debug output" FALSE)

if(BLUEPRINT_DEBUG)
    message(STATUS "BLUEPRINT DEBUG enabled")
    add_definitions(-DBLUEPRINT_DEBUG_ENABLED)
endif()

option(BLUEPRINT_PLACEHOLDER_PROOF_GEN "Build with placeholder proof generation running" FALSE)

if(BLUEPRINT_PLACEHOLDER_PROOF_GEN)
    message(STATUS "BLUEPRINT PROOF GENERATION enabled")
    add_definitions(-DBLUEPRINT_PLACEHOLDER_PROOF_GEN_ENABLED)
endif()

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        crypto3::blueprint
        crypto3::algebra
        crypto3::zk
        crypto3::random
        crypto3::hash
        Boost::unit_test_framework
)
set_target_properties(_cm_internal_tests-crypto3-blueprint-test PROPERTIES CXX_STANDARD 20)
target_precompile_headers(_cm_internal_tests-crypto3-blueprint-test REUSE_FROM crypto3_precompiled_headers)

set(BLUEPRINT_TEST_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

macro(define_custom_blueprint_test test prefix)
    string(REPLACE "." "" _test ${test})
    string(REPLACE "/" "_" full_test_name ${prefix}_${_test}_test)

    if (NOT "${postfix}" STREQUAL "")
        set(full_test_name "${full_test_name}")
    endif()

    set(TEST_RESULTS_DIR "${CMAKE_CURRENT_BINARY_DIR}/junit_results")
    set(TEST_LOGS_DIR "${TEST_RESULTS_DIR}/logs")
    set(additional_args "--log_format=JUNIT"
                        "--log_sink=${TEST_LOGS_DIR}/${full_test_name}.xml")

    cm_test(NAME ${full_test_name} SOURCES ${test}.cpp ARGS ${additional_args})

    target_include_directories(${full_test_name} PRIVATE
                               ${Boost_INCLUDE_DIRS})

    set_target_properties(${full_test_name} PROPERTIES CXX_STANDARD 20)

    target_compile_definitions(${full_test_name} PRIVATE TEST_DATA_DIR="${BLUEPRINT_TEST_ROOT}/zkevm/data/")

    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${full_test_name} PRIVATE "${ARGV2}" "-fconstexpr-steps=2147483647" "-ftemplate-backtrace-limit=0")
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${full_test_name} PRIVATE "${ARGV2}" "-fconstexpr-ops-limit=4294967295" "-ftemplate-backtrace-limit=0")
    endif()

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(${full_test_name} PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()

    target_precompile_headers(${full_test_name} REUSE_FROM crypto3_precompiled_headers)
endmacro()

macro(define_blueprint_test test)
    define_custom_blueprint_test(${test} "blueprint" "")
endmacro()

set(COMMON_TEST_FILES
    "test_plonk_component"
    "manifest"
    "detail/huang_lu"
    "gate_id"
    "utils/connectedness_check"
    "private_input"
    "proxy"
    #"mock/mocked_components"
    "component_batch"
    "bbf/tester"
    "bbf/opcode_poc"
    "bbf/row_seletor_test"
    "bbf/gate_optimizer"
    "bbf/poseidon"
    "bbf/test_circuit_builder"
    "bbf/keccak_round"
    "bbf/keccak_dynamic"
    "bbf/detail/range_check_multi"
    "bbf/detail/carry_on_addition"
    "bbf/detail/choice_function"
    "bbf/algebra/fields/non_native/add_sub_mod_p"
    "bbf/algebra/fields/non_native/check_mod_p"
    "bbf/algebra/fields/non_native/negation_mod_p"
    "bbf/algebra/fields/non_native/flexible_multiplication"
    "bbf/algebra/curves/weierstrass/ec_double"
    "bbf/algebra/curves/weierstrass/ec_full_add"
    "bbf/algebra/curves/weierstrass/ec_incomplete_add"
    "bbf/algebra/curves/weierstrass/ec_two_t_plus_q"
    "bbf/algebra/curves/weierstrass/ec_scalar_mult"
    "bbf/pubkey/ecdsa/ecdsa_recovery"
    )

set(NON_NATIVE_TESTS_FILES
    "algebra/fields/plonk/non_native/multiplication"
    "algebra/fields/plonk/non_native/addition"
    "algebra/fields/plonk/non_native/subtraction"
    "algebra/fields/plonk/non_native/range"
    "algebra/fields/plonk/non_native/reduction"
    "algebra/fields/plonk/non_native/bit_decomposition"
    "algebra/fields/plonk/non_native/bit_composition"
    "algebra/fields/plonk/non_native/bit_shift_constant"
    "algebra/fields/plonk/non_native/comparison_checked"
    "algebra/fields/plonk/non_native/comparison_unchecked"
    "algebra/fields/plonk/non_native/comparison_flag"
    "algebra/fields/plonk/non_native/equality_flag"
    "algebra/fields/plonk/non_native/division_remainder"
    "non_native/plonk/bool_scalar_multiplication"
    "non_native/plonk/add_mul_zkllvm_compatible"
    #"non_native/plonk/scalar_non_native_range"
    )

set(NON_NATIVE_TESTS_FILES_WITH_PROOF_GEN
    "algebra/fields/plonk/non_native/logic_ops"
    "algebra/fields/plonk/non_native/lookup_logic_ops"
)

set(PLONK_TESTS_FILES
    "algebra/curves/plonk/variable_base_scalar_mul"
    "algebra/curves/plonk/unified_addition"
    #"algebra/curves/plonk/variable_base_endo_scalar_mul"
    "algebra/curves/plonk/endo_scalar"
    "hashes/plonk/poseidon"
    "hashes/plonk/sha256"
    "hashes/plonk/sha512"
    "hashes/plonk/sha256_process"
    "hashes/plonk/sha512_process"
    "hashes/plonk/decomposition"
    "hashes/plonk/keccak_component"
    "hashes/plonk/keccak_dynamic"
    #"hashes/plonk/keccak_static" fails with memory access violation
    #"hashes/plonk/keccak_padding" fails with signal: SIGABRT
    "hashes/plonk/keccak_round"
    #"hashes/plonk/detail/sha_table_generators_base4"
    #"hashes/plonk/detail/sha_table_generators_base7"
    "algebra/fields/plonk/field_operations"
    #"algebra/fields/plonk/combined_inner_product"
    "algebra/fields/plonk/exponentiation"
    "algebra/fields/plonk/sqrt"
    "algebra/fields/plonk/range_check"
    "algebra/fields/plonk/logic_and_flag"
    "algebra/fields/plonk/logic_or_flag"
    "algebra/fields/plonk/interpolation"
    "verifiers/placeholder/permutation_argument_verifier"
    "verifiers/placeholder/gate_argument_verifier"
    "verifiers/placeholder/lookup_argument_verifier"
    "verifiers/placeholder/gate_component"
    "verifiers/placeholder/f1_loop"
    "verifiers/placeholder/f3_loop"
    "verifiers/placeholder/fri_cosets"
    "verifiers/placeholder/fri_lin_inter"
    "verifiers/placeholder/fri_array_swap"
    "verifiers/placeholder/expression_evaluation_component"
    "verifiers/placeholder/final_polynomial_check"
    "verifiers/flexible/swap"
    "verifiers/flexible/additions"
    "verifiers/flexible/multiplications"
    "verifiers/flexible/poseidon"
    "verifiers/flexible/constant_pow"
    "verifiers/flexible/pow_factor"
    "verifiers/flexible/linear_check"
    "verifiers/flexible/negate"
    "verifiers/placeholder/verifier"
    "verifiers/placeholder/dfri_verifier"
    "verifiers/placeholder/dfri_input_generator"
    )


set(ZKEVM_TESTS_FILES
    "zkevm/bytecode"
    # "zkevm/rw"
    #"zkevm/copy"
    "zkevm/connections"
    #"zkevm/state_selector"
    "zkevm/zkevm_word"
    #"zkevm/state_transition"
    "zkevm/opcodes/iszero"
    "zkevm/opcodes/add_sub"
    "zkevm/opcodes/mul"
    "zkevm/opcodes/div"
    "zkevm/opcodes/cmp"
    "zkevm/opcodes/pushx"
    "zkevm/opcodes/not"
    "zkevm/opcodes/mod_ops"
    "zkevm/opcodes/byte_ops"
    "zkevm/opcodes/bitwise"
    "zkevm/opcodes/err0"
    "zkevm/opcodes/err1"
    #"zkevm/opcodes/workload"
    "zkevm/opcodes/jumps"
)

SET(ALGEBRA_TESTS_FILES
    ${FIELDS_TESTS_FILES}
    ${CURVES_TESTS_FILES}
    ${PAIRING_TESTS_FILES})

SET(ALL_TESTS_FILES
    ${COMMON_TEST_FILES}
    ${NON_NATIVE_TESTS_FILES}
    ${PLONK_TESTS_FILES}
    ${ALGEBRA_TESTS_FILES}
    ${ZKEVM_TESTS_FILES}
    ${HASHES_TESTS_FILES}
    ${ROUTING_TESTS_FILES}
    ${SCHEMES_TESTS_FILES}
    ${VOTING_TESTS_FILES}
    ${BASIC_COMPONENTS_TESTS_FILES})

foreach(TEST_FILE ${ALL_TESTS_FILES})
    define_blueprint_test(${TEST_FILE})
endforeach()

foreach(TEST_FILE ${NON_NATIVE_TESTS_FILES_WITH_PROOF_GEN})
    define_blueprint_test(${TEST_FILE} ARGS "-DBLUEPRINT_PLACEHOLDER_PROOF_GEN=True")
endforeach()

# long tests built with single and multi-threaded modes
add_subdirectory(zkevm_bbf)
