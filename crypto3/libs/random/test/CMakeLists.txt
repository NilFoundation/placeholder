#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2018-2020 Alexey Moskvin
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
    ${CMAKE_WORKSPACE_NAME}::multiprecision
    Boost::unit_test_framework)
set_target_properties(_cm_internal_tests-crypto3-random-test PROPERTIES CXX_STANDARD 23)
target_precompile_headers(_cm_internal_tests-crypto3-random-test REUSE_FROM crypto3_precompiled_headers)

macro(define_random_test test)
    get_filename_component(name ${test} NAME)
    string(REPLACE "/" "_" full_test_name ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_${test}_test)

    cm_test(NAME ${full_test_name} SOURCES ${test}.cpp)

    target_include_directories(${full_test_name} PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(${full_test_name} PROPERTIES CXX_STANDARD 23)

    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${full_test_name} PRIVATE "-fconstexpr-steps=2147483647")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${full_test_name} PRIVATE "-fconstexpr-ops-limit=4294967295")
    endif()
    target_precompile_headers(${full_test_name} REUSE_FROM crypto3_precompiled_headers)
endmacro()

set(TESTS_NAMES
  "algebraic_engine"
  )

foreach(TEST_NAME ${TESTS_NAMES})
    define_random_test(${TEST_NAME})
endforeach()


include_directories(${CMAKE_WORKSPACE_SOURCES_DIR})
