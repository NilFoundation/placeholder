add_library(proof_producer_preset INTERFACE)

find_package(Boost COMPONENTS REQUIRED log)

target_link_libraries(proof_producer_preset INTERFACE Boost::log proof_producer_types)
target_include_directories(proof_producer_preset INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
