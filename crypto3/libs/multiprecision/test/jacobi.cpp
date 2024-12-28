//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE jacobi_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include "nil/crypto3/multiprecision/big_uint.hpp"
#include "nil/crypto3/multiprecision/jacobi.hpp"
#include "nil/crypto3/multiprecision/literals.hpp"

using namespace nil::crypto3::multiprecision;

template<typename T>
void test() {
    BOOST_CHECK_EQUAL(jacobi(T(5u), T(9u)), 1);
    BOOST_CHECK_EQUAL(jacobi(T(1u), T(27u)), 1);
    BOOST_CHECK_EQUAL(jacobi(T(2u), T(27u)), -1);
    BOOST_CHECK_EQUAL(jacobi(T(3u), T(27u)), 0);
    BOOST_CHECK_EQUAL(jacobi(T(4u), T(27u)), 1);
    BOOST_CHECK_EQUAL(jacobi(T(506u), T(1103u)), -1);

    // new tests from algebra:
    BOOST_CHECK_EQUAL(
        jacobi(T(76749407),
               T("21888242871839275222246405745257275088696311157297823662689037894645226208583")),
        -1);
    BOOST_CHECK_EQUAL(
        jacobi(T(76749407),
               T("52435875175126190479447740508185965837690552500527637822603658699938581184513")),
        -1);
    BOOST_CHECK_EQUAL(jacobi(T(76749407), T("184014718449470976641732519409003087090464839378677150"
                                            "73880837110864239498070802969129867528264353400424"
                                            "032981962325037091562455342195893356806385102540277644"
                                            "37882223571969881035804085174863110178951694406403"
                                            "431417089392760397647317208332132155598016390667992838"
                                            "98191098079351209268491644339667178604494222971572"
                                            "788971054374438281331602764950963417101448891412424011"
                                            "58886206885011341008817780140927978648973063559908"
                                            "134085593076268545817483710423044623820472777162845900"
                                            "87959373746400022332313336095224466892979000905491"
                                            "154007647609104599675915034901101477294892962614518354"
                                            "5025870323741270110314006814529932451772897")),
                      -1);
}

BOOST_AUTO_TEST_SUITE(jacobi_tests)

BOOST_AUTO_TEST_CASE(jacobi_test) {
    test<big_uint<2048>>();

    constexpr auto a = 0x4931a5f_big_uint256;
    constexpr auto b = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001_big_uint256;
    static_assert(jacobi(a, b) == -1, "jacobi error");
    static_assert(jacobi(0x2_big_uint4, 0xb_big_uint4) == -1);
}

BOOST_AUTO_TEST_SUITE_END()
