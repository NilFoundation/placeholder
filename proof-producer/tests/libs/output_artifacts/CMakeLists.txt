add_custom_target(tests_output_artifacts_single_thread)
add_custom_target(tests_output_artifacts_multi_thread)

# Set properties for build target (single or multi thread)
function(set_properties target)
    target_link_libraries(${target} PRIVATE
        GTest::gtest GTest::gtest_main
        proof_generatorOutputArtifacts
    )

    set_target_properties(${target} PROPERTIES
        LINKER_LANGUAGE CXX
        EXPORT_NAME ${target}
        CXX_STANDARD 23
        CXX_STANDARD_REQUIRED TRUE
    )
    target_compile_definitions(${target} PRIVATE TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/resources/")
    gtest_discover_tests(${target})
endfunction()

# Add test for OutputArtifacts library
# .cpp file must have the name of target
function(add_output_artifacts_test target)
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

    target_precompile_headers(${target}_single_thread REUSE_FROM proof_generatorOutputArtifacts)
    target_precompile_headers(${target}_multi_thread  REUSE_FROM proof_generatorOutputArtifacts)

    add_dependencies(tests_output_artifacts_single_thread ${target}_single_thread)
    add_dependencies(tests_output_artifacts_multi_thread ${target}_multi_thread)
endfunction()

add_output_artifacts_test(test_range)
add_output_artifacts_test(test_ranges)
add_output_artifacts_test(test_circuit_writer)
add_output_artifacts_test(test_assignment_table_writer)

file(INSTALL "resources" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
