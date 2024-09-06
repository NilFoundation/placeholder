option(ENABLE_EXECUTABLES_TESTS "Enable tests of executables" TRUE)

if(ENABLE_EXECUTABLES_TESTS)
    add_custom_target(executables_tests)

    add_custom_target(test_run_assigner
        COMMAND $<TARGET_FILE:assigner>
        -b ${CMAKE_SOURCE_DIR}/bin/assigner/example_data/call_block.json
        -t assignment
        -e pallas
        -s ${CMAKE_SOURCE_DIR}/bin/assigner/example_data/state.json
        --log-level debug
        DEPENDS
        $<TARGET_FILE:assigner>
        ${CMAKE_SOURCE_DIR}/bin/assigner/example_data/call_block.json
        ${CMAKE_SOURCE_DIR}/bin/assigner/example_data/state.json
        COMMENT "Running assigner integration test"
        VERBATIM
    )
    add_dependencies(executables_tests test_run_assigner)

    # Initial integration test with generating data on cluster and passing them into assigner
    # Step 1: create Nil CLI config file
    set(block_generator_script ${CMAKE_SOURCE_DIR}/bin/block_generator/block_generator.py)
    add_custom_command(
        OUTPUT test_config.yaml
        COMMAND python3
        ${block_generator_script}
        --mode make-config
        --cli-config-name ${CMAKE_CURRENT_BINARY_DIR}/test_config.yaml
        DEPENDS
        ${block_generator_script}
        COMMENT "Generating Nil CLI config"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        VERBATIM
    )

    # Step 2: generate block and account storage state data, write to the files
    add_custom_command(
        OUTPUT block.json state.json
        COMMAND python3
        ${block_generator_script}
        --mode generate-block
        --cli-config-name ${CMAKE_CURRENT_BINARY_DIR}/test_config.yaml
        --block-config-name ${CMAKE_SOURCE_DIR}/bin/block_generator/example_data/block_config.json
        -o ${CMAKE_CURRENT_BINARY_DIR}/block.json
        -s ${CMAKE_CURRENT_BINARY_DIR}/state.json
        DEPENDS
        ${block_generator_script}
        ${CMAKE_SOURCE_DIR}/bin/block_generator/example_data/block_config.json
        test_config.yaml
        COMMENT "Generating block from config"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}  # It is essential because we have relative paths in block_config.json
        VERBATIM
    )

    # Step 3: run assigner
    add_custom_target(assigner_integration_test
        COMMAND $<TARGET_FILE:assigner>
        -b ${CMAKE_CURRENT_BINARY_DIR}/block.json
        -t assignment
        -e pallas
        -s ${CMAKE_CURRENT_BINARY_DIR}/state.json
        --log-level debug
        DEPENDS
        $<TARGET_FILE:assigner>
        block.json
        state.json
        COMMENT "Running assigner integration test"
        VERBATIM
    )
    # TODO move integration test to the nil repository
    #add_dependencies(executables_tests assigner_integration_test)
endif()
