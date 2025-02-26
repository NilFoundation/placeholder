set(BLUEPRINT_TEST_ROOT "../../../../crypto3/libs/blueprint/test")

include("${BLUEPRINT_TEST_ROOT}/test_macro_definition.cmake")
include("${BLUEPRINT_TEST_ROOT}/zkevm_bbf/zkevm_bbf_tests_list.cmake")
include(CMTest)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

option(ZK_PLACEHOLDER_PROFILING "Build with placeholder profiling" FALSE)
option(ZK_PLACEHOLDER_DEBUG "Build with placeholder debug output" FALSE)

if(ZK_PLACEHOLDER_PROFILING)
    add_definitions(-DZK_PLACEHOLDER_PROFILING_ENABLED)
endif()

if(ZK_PLACEHOLDER_DEBUG)
    add_definitions(-DZK_PLACEHOLDER_DEBUG_ENABLED)
endif()

option(BLUEPRINT_DEBUG "Build with blueprint debug output" FALSE)

if(BLUEPRINT_DEBUG)
    message(STATUS "BLUEPRINT DEBUG enabled")
    add_definitions(-DBLUEPRINT_DEBUG_ENABLED)
endif()

option(BLUEPRINT_PLACEHOLDER_PROOF_GEN "Build with placeholder proof generation running" FALSE)

if(BLUEPRINT_PLACEHOLDER_PROOF_GEN)
    message(STATUS "BLUEPRINT PROOF GENERATION enabled")
    add_definitions(-DBLUEPRINT_PLACEHOLDER_PROOF_GEN_ENABLED)
endif()


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
    define_custom_blueprint_test(${TEST_FILE} "blueprint_multi_thread")
endforeach()
