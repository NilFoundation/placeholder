find_package(Protobuf CONFIG REQUIRED)

file(GLOB PROTO_FILES "proto/*.proto")

foreach(PROTO_FILE ${PROTO_FILES})
    get_filename_component(PROTO_NAME_WE ${PROTO_FILE} NAME_WE)
    get_filename_component(PROTO_DIR ${PROTO_FILE} DIRECTORY)

    set(OUTPUT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include/nil/proof-generator/assigner")
    set(PROTO_HDR "${OUTPUT_DIR}/${PROTO_NAME_WE}.pb.h")
    set(PROTO_SRC "${OUTPUT_DIR}/${PROTO_NAME_WE}.pb.cc")

    add_custom_command(
        OUTPUT ${PROTO_HDR} ${PROTO_SRC}
        COMMAND protobuf::protoc
        ARGS --cpp_out=${OUTPUT_DIR} --proto_path ${PROTO_DIR} ${PROTO_FILE}
        DEPENDS ${PROTO_FILE}
        COMMENT "Generating ${PROTO_SRC} and ${PROTO_HDR} from ${PROTO_FILE}"
        VERBATIM
    )

    list(APPEND GENERATED_SOURCES ${PROTO_SRC})
    list(APPEND GENERATED_HEADERS ${PROTO_HDR})
endforeach()

add_library(proof_generatorAssigner
            ${PROTO_SRC}
)
set_target_properties(proof_generatorAssigner PROPERTIES CXX_STANDARD 20)

target_include_directories(proof_generatorAssigner
                            PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

find_package(Boost REQUIRED COMPONENTS filesystem log)
if(ENABLE_TESTS)
    find_package(Boost REQUIRED COMPONENTS unit_test_framework)
endif()

target_link_libraries(proof_generatorAssigner
                        PUBLIC
                        proof_generatorPreset
                        crypto3::common
                        protobuf::libprotobuf
                        Boost::filesystem
                        Boost::log
)

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(proof_generatorAssigner PRIVATE "-fconstexpr-steps=2147483647")
    
    # without it abseil-cpp fails to link with clang19-compiled code, see https://github.com/llvm/llvm-project/issues/102443
    target_compile_options(proof_generatorAssigner PRIVATE "-fclang-abi-compat=17") 
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(proof_generatorAssigner PRIVATE "-fconstexpr-ops-limit=4294967295")
endif ()

install(TARGETS proof_generatorAssigner
        DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/proto
        DESTINATION ${CMAKE_INSTALL_LIBDIR})
