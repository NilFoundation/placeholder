#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2018-2021 Aleksei Moskvin <alalmoskvin@gmail.com>
# Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

add_custom_target(${CURRENT_PROJECT_NAME}_test_suite)

cm_test_link_libraries(
    ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
    Boost::unit_test_framework
)

macro(define_multiprecision_test name)
    set(test_name "${CURRENT_PROJECT_NAME}_${name}_test")

    cm_test(NAME ${test_name} SOURCES ${name}.cpp ARGS)

    target_include_directories(${test_name} PRIVATE
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
        "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

        ${Boost_INCLUDE_DIRS}
    )

    set_target_properties(${test_name} PROPERTIES CXX_STANDARD 23
        CXX_STANDARD_REQUIRED TRUE)

    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${test_name} PRIVATE "-fconstexpr-steps=2147483647")
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${test_name} PRIVATE "-fconstexpr-ops-limit=4294967295")
    endif()

    target_compile_definitions(${test_name} PRIVATE TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data/")

    add_dependencies(${CURRENT_PROJECT_NAME}_test_suite ${test_name})
endmacro(define_multiprecision_test)

set(MULTIPRECISION_TESTS_NAMES
    "big_mod_basic"
    "big_mod_randomized"
    "big_uint_comparison_randomized"
    "big_uint"
    "inverse"
    "jacobi"
    "miller_rabin"
    "ressol"
)

foreach(TEST_NAME ${MULTIPRECISION_TESTS_NAMES})
    define_multiprecision_test(${TEST_NAME})
endforeach()
