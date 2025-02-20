include(CMTest)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        parallel-crypto3::all
        crypto3::common
        Boost::unit_test_framework
)

set_target_properties(_cm_internal_tests-crypto3-blueprint-multi_thread_tests PROPERTIES CXX_STANDARD 20)

foreach(TEST_FILE ${ZKEVM_BBF_TESTS_FILES})
    define_custom_blueprint_test(${TEST_FILE} "blueprint_zkevm_bbf_multi_thread")
endforeach()
