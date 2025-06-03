set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

include(zkevm_bbf_tests_list.cmake)

include(CMTest)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        crypto3::blueprint
        crypto3::algebra
        crypto3::zk
        crypto3::random
        crypto3::hash
        Boost::unit_test_framework
)

foreach(TEST_FILE ${ZKEVM_BBF_TESTS_FILES})
    define_custom_blueprint_test(${TEST_FILE} "blueprint")
endforeach()

