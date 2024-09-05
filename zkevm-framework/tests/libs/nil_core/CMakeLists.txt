# SSZ++ requires C++23
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(sszpp REQUIRED)

# Add test for NilCore library
# .cpp file must have the name of target
function(add_nil_core_test target)
    add_executable(nil_core_${target} ${target}.cpp)

    target_link_libraries(nil_core_${target} PRIVATE NilCore sszpp::sszpp GTest::gtest_main)

    gtest_discover_tests(nil_core_${target})
endfunction()

add_nil_core_test(test_nil_core_ssz)
add_nil_core_test(test_nil_core_mpt)
