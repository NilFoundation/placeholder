# SSZ++ can be compiled only with GCC 13+
if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    message(FATAL_ERROR "Data types library can be built only with GCC 13+")
endif()
if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 13.0)
    message(FATAL_ERROR "Data types library can be built only with GCC 13+")
endif()

find_package(sszpp REQUIRED)

set(SOURCES
    mpt/mpt.cpp
    mpt/node.cpp
    mpt/path.cpp
)

target_sources(${LIBRARY_NAME} PRIVATE ${SOURCES})

target_link_libraries(${LIBRARY_NAME} PRIVATE sszpp::sszpp)
