option(ENABLE_OUTPUT_ARTIFACTS_TESTS "Enable output artifacts tests" TRUE)
option(ENABLE_ASSIGNER_RUNNER_TESTS "Enable assigner runner tests" TRUE)
option(ENABLE_NIL_CORE_TESTS "Enable Nil Core tests" TRUE)

if (ENABLE_OUTPUT_ARTIFACTS_TESTS)
    add_subdirectory(output_artifacts)
endif()

if (ENABLE_ASSIGNER_RUNNER_TESTS)
    add_subdirectory(assigner_runner)
endif()

if(ENABLE_NIL_CORE_TESTS)
    add_subdirectory(nil_core)
endif()
