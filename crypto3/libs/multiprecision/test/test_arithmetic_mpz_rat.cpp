///////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#ifdef _MSC_VER
#define _SCL_SECURE_NO_WARNINGS
#endif

#include <nil/crypto3/multiprecision/boost_backends/gmp.hpp>
#include <nil/crypto3/multiprecision/boost_backends/rational_adaptor.hpp>

#include "test_arithmetic.hpp"

int main() {
    test<boost::multiprecision::number<
        boost::multiprecision::rational_adaptor<boost::multiprecision::gmp_int>>>();
    return boost::report_errors();
}
