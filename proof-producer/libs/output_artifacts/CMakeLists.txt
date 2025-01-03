add_library(proof_generatorOutputArtifacts 
    src/output_artifacts.cpp
)

target_include_directories(proof_generatorOutputArtifacts
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

find_package(Boost REQUIRED COMPONENTS filesystem log)
if(ENABLE_TESTS)
    find_package(Boost REQUIRED COMPONENTS unit_test_framework)
endif()

target_link_libraries(proof_generatorOutputArtifacts
                      PUBLIC
                      crypto3::common
                      Boost::program_options
                      Boost::log
)

set_target_properties(proof_generatorOutputArtifacts PROPERTIES
    LINKER_LANGUAGE CXX
    EXPORT_NAME proof_generatorOutputArtifacts
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED TRUE
)

install(TARGETS proof_generatorOutputArtifacts
        DESTINATION ${CMAKE_INSTALL_LIBDIR})
        
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
