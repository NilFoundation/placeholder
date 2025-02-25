set(CRYPTO3_BLUEPRINT_TEST_FOLDER "../../../../crypto3/libs/blueprint/test")
set(SOURCES_DIR "${CRYPTO3_BLUEPRINT_TEST_FOLDER}/zkevm_bbf/")

include("${CRYPTO3_BLUEPRINT_TEST_FOLDER}/test_macro_definition.cmake")
include("${CRYPTO3_BLUEPRINT_TEST_FOLDER}/zkevm_bbf/zkevm_bbf_tests_list.cmake")
include(CMTest)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        actor::containers
        actor::math
        actor::zk
        actor::core
        crypto3::common
        Boost::unit_test_framework
)

set_target_properties(_cm_internal_tests--parallel-blueprint-test PROPERTIES CXX_STANDARD 20)

foreach(TEST_FILE ${ZKEVM_BBF_TESTS_FILES})
    define_custom_blueprint_test(${TEST_FILE} "blueprint_zkevm_bbf_multi_thread")
endforeach()
