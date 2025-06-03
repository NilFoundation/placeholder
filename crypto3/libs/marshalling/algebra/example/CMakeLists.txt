#---------------------------------------------------------------------------#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                       crypto3::multiprecision
                       crypto3::algebra
                       ${CMAKE_WORKSPACE_NAME}::marshalling-multiprecision
                       ${CMAKE_WORKSPACE_NAME}::marshalling-core
                   )

macro(define_marshalling_test name)
    set(test_name "marshalling_algebra_${name}_example")

    cm_test(NAME ${test_name} SOURCES ${name}.cpp)

    target_include_directories(${test_name} PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(${test_name} PROPERTIES
                          CXX_STANDARD 23
                          CXX_STANDARD_REQUIRED TRUE)

    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${test_name} PRIVATE "-fconstexpr-steps=2147483647")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${test_name} PRIVATE "-fconstexpr-ops-limit=4294967295")
    endif()

endmacro()

set(TESTS_NAMES
    "curve_element"
    "field_element"
    )

foreach(TEST_NAME ${TESTS_NAMES})
    define_marshalling_test(${TEST_NAME})
endforeach()
