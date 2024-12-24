add_custom_target(tests_prover_single_thread)
add_custom_target(tests_prover_multi_thread)

# Set properties for build target (single or multi thread)
function(set_properties target)
    target_link_libraries(${target} PRIVATE
        GTest::gtest GTest::gtest_main
        proof-producer::include
        proof_generatorAssigner
        proof_generatorPreset
        proof_generatorOutputArtifacts
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
endfunction()

# Add test for Prover class
# .cpp file must have the name of target
function(add_prover_test target)
    add_executable(${target}_single_thread ${target}.cpp)
    add_executable(${target}_multi_thread ${target}.cpp)

    set_properties(${target}_single_thread)
    set_properties(${target}_multi_thread)
    target_link_libraries(${target}_single_thread PRIVATE
        crypto3::all

    )
    target_link_libraries(${target}_multi_thread PRIVATE
        parallel-crypto3::all
        crypto3::common
    )

    if(PROOF_PRODUCER_STATIC_BINARIES)
        # TODO: try to avoid completely static linking here, it's not necessary, but otherwise build fails for some reason
        target_link_options(${target}_single_thread PRIVATE -static -static-libgcc -static-libstdc++)
        target_link_options(${target}_multi_thread PRIVATE -static -static-libgcc -static-libstdc++)
    endif()

    add_dependencies(tests_prover_single_thread ${target}_single_thread)
    add_dependencies(tests_prover_multi_thread ${target}_multi_thread)

    target_precompile_headers(${target}_single_thread REUSE_FROM ${target}_multi_thread)
endfunction()

add_prover_test(test_zkevm_bbf_circuits)

file(INSTALL "resources" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
