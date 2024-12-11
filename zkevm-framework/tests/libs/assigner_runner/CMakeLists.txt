add_executable(assigner_runner_test runner_test.cpp)

target_link_libraries(assigner_runner_test PRIVATE zkEVMAssignerRunner zkEVMPreset GTest::gtest_main ${Boost_LIBRARIES})

target_compile_definitions(assigner_runner_test
                            PRIVATE BLOCK_CONFIG="${CMAKE_CURRENT_LIST_DIR}/../../../bin/assigner/example_data/call_block.json"
                            PRIVATE STATE_CONFIG="${CMAKE_CURRENT_LIST_DIR}/../../../bin/assigner/example_data/state.json")
gtest_discover_tests(assigner_runner_test)
