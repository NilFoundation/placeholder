#---------------------------------------------------------------------------#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

macro(define_hash_example name)
    add_executable(hash_${name}_example ${name}.cpp)
    target_link_libraries(hash_${name}_example PRIVATE
                          ${CMAKE_WORKSPACE_NAME}_hash

                          crypto3::multiprecision
                          Boost::random
                      )

    set_target_properties(hash_${name}_example PROPERTIES CXX_STANDARD 23)
endmacro()

set(EXAMPLES_NAMES
    "hashes")

foreach(EXAMPLE_NAME ${EXAMPLES_NAMES})
    define_hash_example(${EXAMPLE_NAME})
endforeach()
