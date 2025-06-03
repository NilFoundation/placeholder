add_library(proof_producer_output_artifacts
    src/output_artifacts.cpp
)

target_include_directories(proof_producer_output_artifacts
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

find_package(Boost REQUIRED COMPONENTS filesystem log)
if(BUILD_TESTS)
    find_package(Boost REQUIRED COMPONENTS unit_test_framework)
endif()

target_link_libraries(proof_producer_output_artifacts
                      PUBLIC
                      crypto3::common
                      Boost::program_options
                      Boost::log
)

set_target_properties(proof_producer_output_artifacts PROPERTIES
    LINKER_LANGUAGE CXX
    EXPORT_NAME proof_producer_output_artifacts
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED TRUE
)

install(TARGETS proof_producer_output_artifacts
        DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
