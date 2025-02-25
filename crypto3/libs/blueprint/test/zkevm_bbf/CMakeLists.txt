set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
set(SOURCES_DIR "../")

# ../ is a bit of a hack, but since we are going to use the list only from subdirectories, it should be fine
include(zkevm_bbf_tests_list.cmake)

add_subdirectory(single_thread_tests)
