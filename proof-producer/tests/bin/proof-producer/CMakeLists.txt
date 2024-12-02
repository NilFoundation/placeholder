add_custom_target(tests_proof_producer)

# Add test for proof-producer components
# .cpp file must have the name of target
function(add_proof_producer_test target)
    add_executable(${target} ${target}.cpp)

    target_link_libraries(${target} PRIVATE 
        proof-producer::include
        proof_generatorPreset
        proof_generatorAssigner
        proof_generatorOutputArtifacts
        GTest::gtest 
        GTest::gtest_main)

    set_target_properties(${target} PROPERTIES
        LINKER_LANGUAGE CXX
        EXPORT_NAME ${target}
        CXX_STANDARD 23
        CXX_STANDARD_REQUIRED TRUE
    )

    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${target} PRIVATE "-fconstexpr-steps=2147483647")
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${targe} PRIVATE "-fconstexpr-ops-limit=4294967295")
    endif ()

    gtest_discover_tests(${target})
    add_dependencies(tests_proof_producer ${target})
endfunction()

add_proof_producer_test(test_copy_circuit)

file(INSTALL "resources" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
