#---------------------------------------------------------------------------#
# Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMDeploy)
include(CMSetupVersion)

add_executable(circgen
    src/circgen.cpp
)

set_target_properties(circgen PROPERTIES
    LINKER_LANGUAGE CXX
    EXPORT_NAME circgen
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED TRUE)


if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(circgen PRIVATE "-fconstexpr-steps=2147483647")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(circgen PRIVATE "-fconstexpr-ops-limit=4294967295")
endif ()

target_link_libraries(circgen
    crypto3::all
    Boost::filesystem
    Boost::log
    Boost::program_options
)

# Install circgen
install(TARGETS circgen EXPORT debug-toolsTargets DESTINATION ${CMAKE_INSTALL_LIBDIR})
