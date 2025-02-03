add_library(proof_generator_preset INTERFACE)

find_package(Boost COMPONENTS REQUIRED log)

target_link_libraries(proof_generator_preset INTERFACE Boost::log proof_generator_types)
target_include_directories(proof_generator_preset INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
