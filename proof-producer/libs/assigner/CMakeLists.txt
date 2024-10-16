add_library(proof_generatorAssigner SHARED
            src/trace_parser.cpp
)

target_include_directories(proof_generatorAssigner
                            PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

find_package(Boost REQUIRED COMPONENTS filesystem log)
if(ENABLE_TESTS)
    find_package(Boost REQUIRED COMPONENTS unit_test_framework)
endif()

target_link_libraries(proof_generatorAssigner
                        PUBLIC
                        crypto3::common
                        Boost::log
)

install(TARGETS proof_generatorAssigner
        DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
