add_library(proof_generatorPreset INTERFACE)

target_link_libraries(proof_generatorPreset INTERFACE ${Boost_LIBRARIES})
target_include_directories(proof_generatorPreset INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
