cmake_minimum_required(VERSION 3.27)

project(placeholder)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  add_compile_options (-fdiagnostics-color=always)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  add_compile_options (-fcolor-diagnostics)
endif ()

if(DEFINED CMAKE_BUILD_TYPE)
  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -ggdb")
    set(BOOST_FORCEINLINE "OFF") # improves debugging traces
  endif()
endif()

option(SANITIZE "Build sanitizers" FALSE)
if(${SANITIZE})
  add_compile_options(-fsanitize=undefined,address,leak)
  add_link_options(-fsanitize=undefined,address,leak)
endif()

option(PROFILING_ENABLED "Build with profiling enabled" FALSE)
if (${PROFILING_ENABLED})
  add_compile_definitions(PROFILING_ENABLED)
endif()

option(USE_X86_64_V3 "Build with x86-64-v3 microarchitecture level" FALSE)
if (${USE_X86_64_V3})
  add_compile_options(-march=x86-64-v3)
endif()

# Add dummy target for the more efficient reusing of precompiled headers
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/generated-dummy.cpp)
add_library(crypto3_precompiled_headers STATIC ${CMAKE_CURRENT_BINARY_DIR}/generated-dummy.cpp)
set_target_properties(crypto3_precompiled_headers PROPERTIES
    LINKER_LANGUAGE CXX
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED TRUE
)

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/crypto3")
if ((${PARALLEL_CRYPTO3_ENABLE}) OR (${PROOF_PRODUCER_ENABLE}))
  add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/parallel-crypto3")
endif()
if (${PROOF_PRODUCER_ENABLE})
  add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/proof-producer")
endif()
if (${DEBUG_TOOLS_ENABLE})
  add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/debug-tools")
endif()
