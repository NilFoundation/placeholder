add_custom_target(tests_prover)

# Add test for OutputArtifacts library
# .cpp file must have the name of target
function(add_prover_test target)
    add_executable(${target} ${target}.cpp)

    target_link_libraries(${target} PRIVATE
        GTest::gtest GTest::gtest_main
        proof_generatorAssigner
        proof_generatorPreset
        proof_generatorOutputArtifacts
    )

    target_include_directories(${target} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../bin/proof-producer/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../bin/proof-producer/src
    )

    set_target_properties(${target} PROPERTIES
        LINKER_LANGUAGE CXX
        EXPORT_NAME ${target}
        CXX_STANDARD 23
        CXX_STANDARD_REQUIRED TRUE
    )

    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${target} PRIVATE "-fconstexpr-steps=2147483647")
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${target} PRIVATE "-fconstexpr-ops-limit=4294967295")
    endif ()

    target_compile_definitions(${target} PRIVATE TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/resources/traces/")

    gtest_discover_tests(${target})
    add_dependencies(tests_prover ${target})
endfunction()

add_prover_test(test_zkevm_bbf_circuits)

file(INSTALL "resources" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
