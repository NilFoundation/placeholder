
set(COMMON_TEST_FILES
    "test_plonk_component"
    "manifest"
    "detail/huang_lu"
    "gate_id"
    "utils/connectedness_check"
    "private_input"
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
    # Martun: disabling this tests, since it cannot work with out the evaluation proof challenge in the proof.
    # We will enable it once the recursive verifier is fixed.
    # "verifiers/placeholder/verifier"
    "verifiers/placeholder/dfri_verifier"
    "verifiers/placeholder/dfri_input_generator"
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
