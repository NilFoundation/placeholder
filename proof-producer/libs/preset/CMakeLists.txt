add_library(proof_generatorPreset INTERFACE)

find_package(Boost COMPONENTS REQUIRED log)

target_link_libraries(proof_generatorPreset INTERFACE Boost::log proof_generatorTypes)
target_include_directories(proof_generatorPreset INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
