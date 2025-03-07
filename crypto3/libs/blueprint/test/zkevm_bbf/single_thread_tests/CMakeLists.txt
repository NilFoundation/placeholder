include(CMTest)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        crypto3::blueprint
        crypto3::algebra
        crypto3::zk
        crypto3::random
        crypto3::hash
        Boost::unit_test_framework
)

set_target_properties(_cm_internal_tests-crypto3-blueprint-single_thread_tests PROPERTIES CXX_STANDARD 20)

foreach(TEST_FILE ${ZKEVM_BBF_TESTS_FILES})
    define_custom_blueprint_test(${TEST_FILE} "blueprint_single_thread")
endforeach()
