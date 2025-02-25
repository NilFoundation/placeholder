#---------------------------------------------------------------------------#
# Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@gmail.com>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

option(BLUEPRINT_PLACEHOLDER_PROOF_GEN "Build with placeholder proof generation running" FALSE)
if(BLUEPRINT_PLACEHOLDER_PROOF_GEN)
    message(STATUS "BLUEPRINT PROOF GENERATION enabled")
    add_definitions(-DBLUEPRINT_PLACEHOLDER_PROOF_GEN_ENABLED)
endif()

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        crypto3::blueprint
        crypto3::algebra
        crypto3::zk
        crypto3::random
        crypto3::hash
        Boost::unit_test_framework
)
set_target_properties(_cm_internal_tests-crypto3-blueprint-test PROPERTIES CXX_STANDARD 20)
target_precompile_headers(_cm_internal_tests-crypto3-blueprint-test REUSE_FROM crypto3_precompiled_headers)

set(BLUEPRINT_TEST_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

include(test_macro_definition.cmake)
include(define_common_tests.cmake)
include(define_non_native_with_proof_generation.cmake)

# long tests built with single and multi-threaded modes
add_subdirectory(zkevm_bbf)
