include(GoogleTest)

find_package(GTest CONFIG REQUIRED)

add_executable(assigner_tests
               assigner_test.cpp)

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(assigner_tests PRIVATE "-fconstexpr-steps=2147483647")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(assigner_tests PRIVATE "-fconstexpr-ops-limit=4294967295")
endif()

target_include_directories(assigner_tests PRIVATE
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../evmc>)

target_link_libraries(
        assigner_tests
        PRIVATE
        ${PROJECT_NAME}
        GTest::gtest_main
        Boost::log
)
gtest_discover_tests(assigner_tests PROPERTIES LABELS ASSIGNER)

add_custom_target(run_assigner_tests COMMAND ${CMAKE_CTEST_COMMAND} -L ASSIGNER --output-on-failure WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_dependencies(run_assigner_tests assigner_tests)
