include(CMConfig)
include(CMSetupVersion)

cm_workspace(crypto3)
cm_project(marshalling-core WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES C CXX)

include(CMDeploy)
include(FindPkgConfig)

include(CMSetupVersion)

option(BUILD_WITH_NO_WARNINGS "Build threading warnings as errors" FALSE)

# When set, the code always throws on invalid data.
# If not set, the code is using BOOST_VERIFY - noop in release and stop in debug
option(CRYPTO3_MARSHALLING_THROWS "Throw exceptions when marshalling invalid data" TRUE)

if(CRYPTO3_MARSHALLING_THROWS)
    add_definitions(-DCRYPTO3_MARSHALLING_THROWS)
endif()

if(NOT CMAKE_CXX_STANDARD)
    set_target_properties(${test_name} PROPERTIES CXX_STANDARD 23)
endif()

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)
add_library(${CMAKE_WORKSPACE_NAME}::${CURRENT_PROJECT_NAME} ALIAS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                      EXPORT_NAME ${CURRENT_PROJECT_NAME})

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                           $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>

                           $<$<BOOL:${Boost_FOUND}>:${Boost_INCLUDE_DIRS}>)

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
    crypto3::algebra
    Boost::container)

include(CMTest)
add_tests(test)

if(BUILD_EXAMPLES)
    add_subdirectory(example)
endif()

if((CMAKE_COMPILER_IS_GNUCC) OR ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang"))
    set(extra_flags_list -Wall -Wextra -Wcast-align -Wcast-qual
        -Wctor-dtor-privacy -Wmissing-include-dirs -Woverloaded-virtual
        -Wredundant-decls -Wshadow -Wundef -Wunused -Wno-unknown-pragmas
        -fdiagnostics-show-option)

    if(CMAKE_COMPILER_IS_GNUCC)
        list(APPEND extra_flags_list -Wnoexcept -Wlogical-op -Wstrict-null-sentinel)

        if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "4.8")
            list(APPEND extra_flags_list -Wno-pragmas -Wno-type-limits)
        endif()

    endif()

    if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
        list(APPEND extra_flags_list -Wno-dangling-field -Wno-unused-command-line-argument)
    endif()

    if(NOT BUILD_WITH_NO_WARNINGS)
        list(APPEND extra_flags_list -Werror)
    endif()

    target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE ${extra_flags})

    if(NOT BUILD_SHARED_LIBS AND NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++ -static-libgcc")
    endif()
elseif(MSVC)

    add_definitions("/wd4503" "/wd4309" "/wd4267" "-D_SCL_SECURE_NO_WARNINGS")

    if(NOT BUILD_WITH_NO_WARNINGS)
        add_definitions("/WX")
    endif()

    if(NOT BUILD_SHARED_LIBS)
        foreach(flag_var
                CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
                CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
            if(${flag_var} MATCHES "/MD")
                string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
            endif()
        endforeach()
    endif()
endif()

if(CMAKE_TOOLCHAIN_FILE AND EXISTS ${CMAKE_TOOLCHAIN_FILE})
    message(STATUS "Loading toolchain from ${CMAKE_TOOLCHAIN_FILE}")
endif()

find_package(Doxygen)
if(DOXYGEN_FOUND)
    set(doc_output_dir "${DOC_INSTALL_DIR}/marshalling")
    make_directory(${doc_output_dir})

    set(match_str "OUTPUT_DIRECTORY[^\n]*")
    set(replacement_str "OUTPUT_DIRECTORY = ${doc_output_dir}")
    set(output_file "${CMAKE_CURRENT_BINARY_DIR}/docs/doxygen.conf")

    set(config_file "${CMAKE_CURRENT_SOURCE_DIR}/docs/doxygen.conf")
    file(READ ${config_file} config_text)
    string(REGEX REPLACE "${match_str}" "${replacement_str}" modified_config_text "${config_text}")
    file(WRITE "${output_file}" "${modified_config_text}")

    add_custom_target("doc_${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}"
                      COMMAND ${DOXYGEN_EXECUTABLE} ${output_file}
                      COMMAND ${CMAKE_COMMAND} -DDOC_OUTPUT_DIR="${doc_output_dir}" -P
                      ${CMAKE_SOURCE_DIR}/cmake/DocCleanupScript.cmake
                      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endif()

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
