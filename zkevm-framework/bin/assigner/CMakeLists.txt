set(TARGET_NAME assigner)
set(SOURCES
    src/main.cpp
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(${TARGET_NAME} ${SOURCES})

target_include_directories(${TARGET_NAME}
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(${TARGET_NAME}
    PRIVATE
    zkEVMPreset
    zkEVMAssignerRunner
    zkEVMJsonHelpers
    zkEVMOutputArtifacts
    proof-producer-multi-threaded-lib
    ${Boost_LIBRARIES}
)

install(TARGETS ${TARGET_NAME})
