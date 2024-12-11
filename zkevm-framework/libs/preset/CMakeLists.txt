add_library(zkEVMPreset INTERFACE)

target_link_libraries(zkEVMPreset INTERFACE ${Boost_LIBRARIES} evm-assigner)
target_include_directories(zkEVMPreset INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
