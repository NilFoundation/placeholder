#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                      crypto3::algebra
                      crypto3::hash
                      crypto3::marshalling-algebra
                      crypto3::marshalling-zk
                      crypto3::math
                      crypto3::random
                      crypto3::zk
                      Boost::unit_test_framework
)
set_target_properties(_cm_internal_tests-crypto3-transpiler-test PROPERTIES CXX_STANDARD 23)
target_precompile_headers(_cm_internal_tests-crypto3-transpiler-test REUSE_FROM crypto3_precompiled_headers)

add_custom_target(compile_and_run_transpiler_tests)

macro(define_transpiler_test name)
    set(full_test_name transpiler_${name}_test)
    cm_test(NAME ${full_test_name} SOURCES ${name}.cpp)

    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${full_test_name} PRIVATE "-fconstexpr-steps=2147483647")
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${full_test_name} PRIVATE "-fconstexpr-ops-limit=4294967295")
    endif ()

    target_include_directories(${full_test_name} PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(${full_test_name} PROPERTIES CXX_STANDARD 23)

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(${full_test_name} PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()
    add_custom_target(${full_test_name}_run
        COMMAND $<TARGET_FILE:${full_test_name}>
        DEPENDS ${full_test_name} $<TARGET_FILE:${full_test_name}>
    )
    add_dependencies(compile_and_run_transpiler_tests ${full_test_name}_run)

    target_precompile_headers(${full_test_name} REUSE_FROM crypto3_precompiled_headers)
endmacro()

set(TESTS_NAMES
    "evm"
    "recursion"
)

foreach(TEST_NAME ${TESTS_NAMES})
    define_transpiler_test(${TEST_NAME})
endforeach()
