#---------------------------------------------------------------------------//
#  MIT License
#
#  Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
#  Copyright (c) 2021-2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in all
#  copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#  SOFTWARE.
#---------------------------------------------------------------------------//

include(CMTest)

if (NOT Boost_UNIT_TEST_FRAMEWORK_FOUND)
    cm_find_package(Boost REQUIRED COMPONENTS unit_test_framework)
endif ()

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        ${CMAKE_WORKSPACE_NAME}::core
        ${CMAKE_WORKSPACE_NAME}::network
        ${CMAKE_WORKSPACE_NAME}::testing
        epoll-shim

        crypto3::algebra
        crypto3::hash
        crypto3::containers

        ${Boost_LIBRARIES})

macro(define_storage_test test)
    get_filename_component(name ${test} NAME)
    string(REPLACE "-" "_" target_name ${CURRENT_PROJECT_NAME}_${name}_test)

    while (TARGET ${target_name})
        get_filename_component(TEST_DIRECTORY ${test} DIRECTORY)
        get_filename_component(PARENT_DIR ${TEST_DIRECTORY} DIRECTORY)
        set(target_name ${PARENT_DIR}_${target_name})
    endwhile ()

    cm_test(NAME ${target_name} SOURCES ${test}.cpp)

    target_include_directories(${target_name} PRIVATE
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
            "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

            ${Boost_INCLUDE_DIRS})

    set_target_properties(${target_name} PROPERTIES CXX_STANDARD 17)

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if (target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(${target_name} PRIVATE BOOST_TEST_DYN_LINK)
    elseif (target_type STREQUAL "STATIC_LIB")

    endif ()
endmacro()

set(TESTS_NAMES
        "merkle/merkle"
        )

foreach (TEST_NAME ${TESTS_NAMES})
    define_storage_test(${TEST_NAME})
endforeach ()


function(actor_add_test name)
    set(test_kinds
            ACTOR
            BOOST
            CUSTOM)

    cmake_parse_arguments(parsed_args
            ""
            "WORKING_DIRECTORY;KIND"
            "RUN_ARGS;SOURCES;LIBRARIES;DEPENDS"
            ${ARGN})

    if(NOT parsed_args_KIND)
        set(parsed_args_KIND ACTOR)
    elseif(NOT (parsed_args_KIND IN_LIST test_kinds))
        message(FATAL_ERROR "Invalid test kind. KIND must be one of ${test_kinds}")
    endif()

    if(parsed_args_SOURCES)
        #
        # Each kind of test must populate the `args` and `libraries` lists.
        #

        set(libraries "${parsed_args_LIBRARIES}")

        set(args "")
        if(parsed_args_KIND STREQUAL "ACTOR")
            list(APPEND libraries
                    actor::core
                    actor::network
                    ${CMAKE_WORKSPACE_NAME}::testing)

            list(APPEND args -- -c ${BUILD_WITH_UNIT_TEST_SMP})
        elseif(parsed_args_KIND STREQUAL "BOOST")
            list(APPEND libraries
                    ${CMAKE_WORKSPACE_NAME}::core
                    ${CMAKE_WORKSPACE_NAME}::network
                    ${CMAKE_WORKSPACE_NAME}::testing)
        endif()

        if(NOT (UNIX AND (CMAKE_SYSTEM_NAME STREQUAL "Linux")))
            list(APPEND libraries epoll-shim)
        endif()

        list(APPEND args ${parsed_args_RUN_ARGS})

        cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                ${libraries}
                ${Boost_LIBRARIES})

        cm_test(NAME ${CMAKE_WORKSPACE_NAME}_${name}_test SOURCES ${parsed_args_SOURCES})

        target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${name}_test PRIVATE
                ACTOR_TESTING_MAIN BOOST_TEST_DYN_LINK)

        if((BUILD_WITH_STACK_GUARDS STREQUAL "ON") OR
        ((BUILD_WITH_STACK_GUARDS STREQUAL "DEFAULT") AND
        (CMAKE_BUILD_TYPE IN_LIST ACTOR_STACK_GUARD_MODES)))
            target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${name}_test
                    PRIVATE ACTOR_THREAD_STACK_GUARDS)
        endif()

        target_include_directories(${CMAKE_WORKSPACE_NAME}_${name}_test PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}
                ${BUILD_WITH_SOURCE_DIR}/src)

        set_target_properties(${CMAKE_WORKSPACE_NAME}_${name}_test PROPERTIES
                CXX_STANDARD 17
                CXX_STANDARD_REQUIRED TRUE)

        target_compile_options(${CMAKE_WORKSPACE_NAME}_${name}_test PRIVATE
                ${${CURRENT_PROJECT_NAME}_PRIVATE_CXX_FLAGS})
    else()
        if(NOT (parsed_args_KIND STREQUAL "CUSTOM"))
            message(FATAL_ERROR "SOURCES are required for ${parsed_args_KIND} tests")
        endif()
    endif()
endfunction()

actor_add_test(merkle_actor_zerg SOURCES merkle/merkle.cpp)