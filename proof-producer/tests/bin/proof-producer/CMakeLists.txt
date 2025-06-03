add_custom_target(tests_prover)

# Set properties for build target
function(set_properties target)
    target_link_libraries(${target} PRIVATE
        GTest::gtest GTest::gtest_main
        proof-producer::include
        proof_producer_assigner
        proof_producer_preset
        proof_producer_output_artifacts
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
    add_executable(${target} ${target}.cpp)

    set_properties(${target})
    target_link_libraries(${target} PRIVATE crypto3::all)

    if(PROOF_PRODUCER_STATIC_BINARIES)
        # TODO: try to avoid completely static linking here, it's not necessary, but otherwise build fails for some reason
        target_link_options(${target} PRIVATE -static -static-libgcc -static-libstdc++)
    endif()

    add_dependencies(tests_prover ${target})

    target_precompile_headers(${target} REUSE_FROM crypto3_precompiled_headers)
endfunction()

add_prover_test(test_zkevm_bbf_circuits)

file(INSTALL "resources" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
