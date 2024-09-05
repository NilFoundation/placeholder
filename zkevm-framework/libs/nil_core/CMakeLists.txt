set(LIBRARY_NAME NilCore)

find_package(intx REQUIRED)
find_package(sszpp REQUIRED)

# SSZ++ can be compiled only with GCC 13+
if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    message(FATAL_ERROR "NilCore library can be built only with GCC 13+")
endif()

if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 13.0)
    message(FATAL_ERROR "NilCore library can be built only with GCC 13+")
endif()

add_library(${LIBRARY_NAME} SHARED)

add_subdirectory(src)

target_compile_features(${LIBRARY_NAME} PUBLIC cxx_std_23)

target_include_directories(${LIBRARY_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(${LIBRARY_NAME} PUBLIC intx::intx sszpp::sszpp)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
