cmake_minimum_required(VERSION 3.27)

project(placeholder)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  add_compile_options (-fdiagnostics-color=always)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  add_compile_options (-fcolor-diagnostics)
endif ()

if(DEFINED CMAKE_BUILD_TYPE AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -ggdb")
    set(BOOST_FORCEINLINE "OFF") # improves debugging traces
endif()

option(SANITIZE "Build sanitizers" FALSE)
if(${SANITIZE})
  add_compile_options(-fsanitize=undefined,address,leak)
  add_link_options(-fsanitize=undefined,address,leak)
endif()


add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/crypto3")
if ((${PARALLEL_CRYPTO3_ENABLE}) OR (${PROOF_PRODUCER_ENABLE}) OR (${ZKEVM_FRAMEWORK_ENABLE}))
  add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/parallel-crypto3")
endif()
if (${ZKEVM_FRAMEWORK_ENABLE})
  add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/evm-assigner")
  add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/zkevm-framework")
endif()
if ((${PROOF_PRODUCER_ENABLE}) OR (${ZKEVM_FRAMEWORK_ENABLE}))
  add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/proof-producer")
endif()
if (${DEBUG_TOOLS_ENABLE})
  add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/debug-tools")
endif()
