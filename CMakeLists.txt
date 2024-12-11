cmake_minimum_required(VERSION 3.27)

project(placeholder)

set(Boost_DEBUG ON)
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)

find_package(Boost REQUIRED COMPONENTS ALL)
message("${Boost_FOUND}")

message("Boost_INCLUDE_DIRS: ${Boost_INCLUDE_DIRS}")
message("Boost_LIBRARY_DIRS: ${Boost_LIBRARY_DIRS}")
message("Boost_LIBRARIES: ${Boost_LIBRARIES}")



message("\n\n\n\nBoost_LIBRARIES: ${Boost_LIBRARIES}")

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  add_compile_options (-fdiagnostics-color=always)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  add_compile_options (-fcolor-diagnostics)
endif ()

if(DEFINED CMAKE_BUILD_TYPE)
  if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
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
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED TRUE
)

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/generated-dummy-23.cpp)
add_library(crypto3_precompiled_headers_23 STATIC ${CMAKE_CURRENT_BINARY_DIR}/generated-dummy-23.cpp)
set_target_properties(crypto3_precompiled_headers_23 PROPERTIES
    LINKER_LANGUAGE CXX
    EXPORT_NAME proof_generatorOutputArtifacts
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED TRUE
)
# End of precompiled headers

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/crypto3")
if ((${PARALLEL_CRYPTO3_ENABLE}) OR (${PROOF_PRODUCER_ENABLE}) OR (${ZKEVM_FRAMEWORK_ENABLE}))
  add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/parallel-crypto3")
endif()
if ((${PROOF_PRODUCER_ENABLE}) OR (${ZKEVM_FRAMEWORK_ENABLE}))
  add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/proof-producer")
endif()
if (${DEBUG_TOOLS_ENABLE})
  add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/debug-tools")
endif()
