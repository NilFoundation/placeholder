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

macro(define_multiprecision_test_variant name disable_intrinsics disable_int128)
    set(test_name "${CURRENT_PROJECT_NAME}-")

    if (${disable_intrinsics} OR ${disable_int128})
        if (${disable_intrinsics})
            set(test_name "${test_name}no_intrinsics")
        endif()
        if (${disable_int128})
            if (${disable_intrinsics})
                set(test_name "${test_name}_")
            endif()
            set(test_name "${test_name}no_int128")
        endif()
    else()
        set(test_name "${test_name}all_features")
    endif()

    set(test_name "${test_name}-${name}_test")

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

    if (${disable_intrinsics})
        target_compile_definitions(${test_name} PRIVATE NIL_CO3_MP_DISABLE_INTRINSICS)
    endif()

    if (${disable_int128})
        target_compile_definitions(${test_name} PRIVATE NIL_CO3_MP_DISABLE_INT128)
    endif()

    add_dependencies(${CURRENT_PROJECT_NAME}_test_suite ${test_name})
endmacro(define_multiprecision_test_variant)

macro(define_multiprecision_test_variants name)
    define_multiprecision_test_variant(${name} 0 0)
    define_multiprecision_test_variant(${name} 1 0)
    define_multiprecision_test_variant(${name} 0 1)
    define_multiprecision_test_variant(${name} 1 1)
endmacro(define_multiprecision_test_variants)

set(MULTIPRECISION_TESTS_NAMES
    "big_mod_basic"
    "big_mod_randomized"
    "big_uint_basic"
    "big_uint_manual"
    "big_uint_import_export_round_trip"
    "big_uint_randomized"
    "integer"
    "inverse"
    "jacobi"
    "miller_rabin"
    "ressol"
)

foreach(TEST_NAME ${MULTIPRECISION_TESTS_NAMES})
    define_multiprecision_test_variants(${TEST_NAME})
endforeach()
