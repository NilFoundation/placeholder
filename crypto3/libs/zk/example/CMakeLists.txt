#---------------------------------------------------------------------------#
# Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/../include"
        "${CMAKE_CURRENT_BINARY_DIR}/include"

        ${Boost_INCLUDE_DIRS})

macro(define_zk_example name)
    add_executable(zk_${name}_example ${name}.cpp)
    target_link_libraries(zk_${name}_example PRIVATE
            ${CMAKE_WORKSPACE_NAME}::algebra
            ${CMAKE_WORKSPACE_NAME}::hash
            ${CMAKE_WORKSPACE_NAME}::multiprecision
            ${CMAKE_WORKSPACE_NAME}::zk

            Boost::container)
    set_target_properties(zk_${name}_example PROPERTIES CXX_STANDARD 23)
endmacro()

set(EXAMPLES_NAMES
    "transcript"
    "fri"
    "kzg"
)

foreach(EXAMPLE_NAME ${EXAMPLES_NAMES})
    define_zk_example(${EXAMPLE_NAME})
endforeach()
