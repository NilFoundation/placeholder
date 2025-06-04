#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

find_package(Boost REQUIRED COMPONENTS
    timer
    unit_test_framework
)

macro(define_bench_test name)
    set(test_name "crypto3_${name}_bench")

    set(additional_args "")
    if(ENABLE_JUNIT_TEST_OUTPUT)
        set(TEST_RESULTS_DIR "${CMAKE_CURRENT_BINARY_DIR}/junit_results")
        set(TEST_LOGS_DIR "${TEST_RESULTS_DIR}/logs")
        file(MAKE_DIRECTORY ${TEST_LOGS_DIR})

        set(additional_args "--log_format=JUNIT"
                            "--log_sink=${TEST_LOGS_DIR}/${test_name}.xml")
    endif()

    cm_test(NAME ${test_name} SOURCES ${name}.cpp ARGS ${additional_args})

    target_include_directories(${test_name} PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(${test_name} PROPERTIES CXX_STANDARD 23)
    target_precompile_headers(${test_name} REUSE_FROM crypto3_precompiled_headers)
endmacro()

cm_test_link_libraries(
    crypto3::algebra
    crypto3::math
    crypto3::multiprecision
    crypto3::random
    crypto3::core
    Boost::unit_test_framework
    Boost::timer
)

set(TESTS_NAMES
    "polynomial_dfs_benchmark"
)

foreach(TEST_NAME ${TESTS_NAMES})
    define_bench_test(${TEST_NAME})
endforeach()
