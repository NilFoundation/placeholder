#---------------------------------------------------------------------------#
# Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

if(NOT Boost_UNIT_TEST_FRAMEWORK_FOUND)
    cm_find_package(Boost REQUIRED COMPONENTS unit_test_framework)
endif()

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                       Boost::container
                       Boost::unit_test_framework
)

macro(define_actor_core_test name)
    set(test_name "actor_core_${name}_test")

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

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(${test_name} PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()
endmacro()

set(TESTS_NAMES
    "thread_pool")

foreach(TEST_NAME ${TESTS_NAMES})
    define_actor_core_test(${TEST_NAME})
endforeach()
