cmake_minimum_required(VERSION 3.27)

project(placeholder)

option(GPU_PROVER "Enable GPU support" OFF)
if (GPU_PROVER)
  add_compile_options(-DGPU_PROVER)
endif()
add_compile_options(-DPROFILING_ENABLED)

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

# Add dummy target for the more efficient reusing of precompiled headers
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/generated-dummy.cpp)
add_library(crypto3_precompiled_headers STATIC ${CMAKE_CURRENT_BINARY_DIR}/generated-dummy.cpp)
set_target_properties(crypto3_precompiled_headers PROPERTIES
    LINKER_LANGUAGE CXX
    CXX_STANDARD 23
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
