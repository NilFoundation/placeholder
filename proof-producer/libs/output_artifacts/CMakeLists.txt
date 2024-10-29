add_library(proof_generatorOutputArtifacts INTERFACE)

target_include_directories(proof_generatorOutputArtifacts
    INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include
)

find_package(Boost REQUIRED COMPONENTS filesystem log)
if(ENABLE_TESTS)
    find_package(Boost REQUIRED COMPONENTS unit_test_framework)
endif()

target_link_libraries(proof_generatorOutputArtifacts
                      INTERFACE
                      crypto3::common
                      Boost::log
)

install(TARGETS proof_generatorOutputArtifacts
        DESTINATION ${CMAKE_INSTALL_LIBDIR})
        
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
