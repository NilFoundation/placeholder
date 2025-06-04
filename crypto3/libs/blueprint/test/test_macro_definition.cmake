macro(define_custom_blueprint_test test prefix)
    string(REPLACE "${BLUEPRINT_TEST_ROOT}" "" _test ${test})
    string(REPLACE "." "" _test ${_test})
    string(REPLACE "/" "_" full_test_name ${prefix}_${_test}_test)
    string(REGEX REPLACE "_+" "_" full_test_name ${full_test_name})

    set(TEST_RESULTS_DIR "${CMAKE_CURRENT_BINARY_DIR}/junit_results")
    set(TEST_LOGS_DIR "${TEST_RESULTS_DIR}/logs")
    set(additional_args "--log_format=JUNIT"
                        "--log_sink=${TEST_LOGS_DIR}/${full_test_name}.xml")

    cm_test(NAME ${full_test_name} SOURCES ${test}.cpp ARGS ${additional_args})

    target_include_directories(${full_test_name} PRIVATE
                               ${Boost_INCLUDE_DIRS})

    set_target_properties(${full_test_name} PROPERTIES CXX_STANDARD 23)

    file(INSTALL "${BLUEPRINT_TEST_ROOT}/zkevm_bbf/data" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")

    target_compile_definitions(${full_test_name} PRIVATE TEST_DATA_DIR="${CMAKE_CURRENT_BINARY_DIR}/data/")

    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${full_test_name} PRIVATE "${ARGV2}" "-fconstexpr-steps=2147483647" "-ftemplate-backtrace-limit=0")
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${full_test_name} PRIVATE "${ARGV2}" "-fconstexpr-ops-limit=4294967295" "-ftemplate-backtrace-limit=0")
    endif()

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(${full_test_name} PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()

    target_precompile_headers(${full_test_name} REUSE_FROM crypto3_precompiled_headers)
endmacro()

macro(define_blueprint_test test)
    define_custom_blueprint_test(${test} "blueprint" "")
endmacro()
