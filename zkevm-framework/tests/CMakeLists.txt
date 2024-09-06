# GoogleTest requires C++14
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(GTest REQUIRED)

include(GoogleTest)

add_subdirectory(bin)
add_subdirectory(libs)
