find_package(Protobuf CONFIG REQUIRED)

file(GLOB PROTO_FILES "proto/*.proto")

add_library(proof_producer_proto OBJECT ${PROTO_FILES})
target_link_libraries(proof_producer_proto PUBLIC protobuf::libprotobuf)

set(PROTO_BINARY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include/nil/proof-generator/assigner")
target_include_directories(proof_producer_proto PUBLIC "$<BUILD_INTERFACE:${PROTO_BINARY_DIR}>")

protobuf_generate(
    TARGET proof_producer_proto
    IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/proto"
    PROTOC_OUT_DIR "${PROTO_BINARY_DIR}"
)

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    # without it abseil-cpp fails to link with clang19-compiled code, see https://github.com/llvm/llvm-project/issues/102443
    target_compile_options(proof_producer_proto PRIVATE "-fclang-abi-compat=17")
endif()

# Write header file with version of trace proto spec
set(PROTO_HASH_HEADER "${CMAKE_CURRENT_BINARY_DIR}/proto_hash.h")
add_custom_command(
                   OUTPUT ${PROTO_HASH_HEADER}
                   COMMAND bash -c "echo \"#pragma once\" > ${PROTO_HASH_HEADER}"
                   COMMAND bash -c "echo \"#define PROTO_HASH \\\"`cat ${CMAKE_CURRENT_SOURCE_DIR}/proto/*.proto | sha256sum | awk '{print $1}'`\\\"\" >> ${PROTO_HASH_HEADER}"
                   VERBATIM)

add_library(proof_producer_assigner)
target_sources(proof_producer_assigner
    PRIVATE
        $<TARGET_OBJECTS:proof_producer_proto>
        ${PROTO_HASH_HEADER}
)
set_target_properties(proof_producer_assigner PROPERTIES CXX_STANDARD 23)

target_include_directories(proof_producer_assigner
                            PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_BINARY_DIR}
)

find_package(Boost REQUIRED COMPONENTS filesystem log)
if(BUILD_TESTS)
    find_package(Boost REQUIRED COMPONENTS unit_test_framework)
endif()

target_link_libraries(proof_producer_assigner
                        PUBLIC
                        proof_producer_types
                        proof_producer_preset
                        crypto3::common
                        protobuf::libprotobuf
                        Boost::filesystem
                        Boost::log
)

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(proof_producer_assigner PRIVATE "-fconstexpr-steps=2147483647")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(proof_producer_assigner PRIVATE "-fconstexpr-ops-limit=4294967295")
endif ()

install(TARGETS proof_producer_assigner
        DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/proto
        DESTINATION ${CMAKE_INSTALL_LIBDIR})
