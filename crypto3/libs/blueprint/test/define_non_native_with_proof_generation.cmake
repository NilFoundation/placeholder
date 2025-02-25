
set(NON_NATIVE_TESTS_FILES_WITH_PROOF_GEN
    "algebra/fields/plonk/non_native/logic_ops"
    "algebra/fields/plonk/non_native/lookup_logic_ops"
)

foreach(TEST_FILE ${NON_NATIVE_TESTS_FILES_WITH_PROOF_GEN})
    define_blueprint_test(${TEST_FILE} ARGS "-DBLUEPRINT_PLACEHOLDER_PROOF_GEN=True")
endforeach()
