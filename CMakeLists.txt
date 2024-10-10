cmake_minimum_required(VERSION 3.27)

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/crypto3")
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/parallel-crypto3")
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/evm-assigner")
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/proof-producer")
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/zlevm-framework")
