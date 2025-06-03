add_custom_target(tests_output_artifacts)

# Set properties for build target
function(set_properties target)
    target_link_libraries(${target} PRIVATE
        GTest::gtest GTest::gtest_main
        proof_producer_output_artifacts
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
    add_executable(${target} ${target}.cpp)

    set_properties(${target})
    target_link_libraries(${target} PRIVATE crypto3::all)

    if(PROOF_PRODUCER_STATIC_BINARIES)
        # TODO: try to avoid completely static linking here, it's not necessary, but otherwise build fails for some reason
        target_link_options(${target} PRIVATE -static -static-libgcc -static-libstdc++)
    endif()

    target_precompile_headers(${target} REUSE_FROM proof_producer_output_artifacts)

    add_dependencies(tests_output_artifacts ${target})
endfunction()

add_output_artifacts_test(test_range)
add_output_artifacts_test(test_ranges)
add_output_artifacts_test(test_circuit_writer)
add_output_artifacts_test(test_assignment_table_writer)

file(INSTALL "resources" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
