add_library(zkEVMRpc SHARED data_extractor.cpp)

find_package(Boost COMPONENTS REQUIRED json log)
target_link_libraries(zkEVMRpc PUBLIC NilCore ${Boost_LIBRARIES} zkEVMJsonHelpers)
target_include_directories(zkEVMRpc PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
                                PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/include)

install(TARGETS zkEVMRpc
        DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
