option(ENABLE_OUTPUT_ARTIFACTS_TESTS "Enable output artifacts tests" TRUE)

if (ENABLE_OUTPUT_ARTIFACTS_TESTS)
    add_subdirectory(output_artifacts)
endif()
