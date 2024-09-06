# Using <expected>
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add test for OutputArtifacts library
# .cpp file must have the name of target
function(add_output_artifacts_test target)
    add_executable(${target} ${target}.cpp)

    target_link_libraries(${target} PRIVATE zkEVMOutputArtifacts)
    target_link_libraries(${target} PRIVATE GTest::gtest_main)

    gtest_discover_tests(${target})
endfunction()

add_output_artifacts_test(test_range)
add_output_artifacts_test(test_ranges)
