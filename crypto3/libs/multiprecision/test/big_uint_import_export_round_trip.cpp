//---------------------------------------------------------------------------//
// Copyright (c) 2015 John Maddock
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE big_uint_import_export_round_trip_test

#include <algorithm>
#include <cstddef>
#include <iostream>
#include <iterator>
#include <limits>
#include <vector>

#include <boost/test/unit_test.hpp>

#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>

#include "nil/crypto3/multiprecision/big_uint.hpp"

template<class T>
T generate_random() {
    static_assert(
        std::numeric_limits<T>::is_specialized && std::numeric_limits<T>::is_bounded &&
            std::numeric_limits<T>::is_integer && std::numeric_limits<T>::radix == 2,
        "Only integer types are supported");

    static boost::random::uniform_int_distribution<std::size_t> len_distr(
        1, std::numeric_limits<T>::digits);
    static boost::random::mt19937 gen;
    std::size_t len = len_distr(gen);
    boost::random::uniform_int_distribution<T> num_distr(
        T(1) << (len - 1),
        len == std::numeric_limits<T>::digits ? ~T(0) : (T(1) << len) - 1);
    return num_distr(gen);
}

template<class T>
void test_round_trip(T val) {
    std::vector<unsigned char> cv;
    val.export_bits(std::back_inserter(cv), 8);
    T newval;
    newval.import_bits(cv.begin(), cv.end());
    BOOST_CHECK_EQUAL(val, newval);
    // Should get the same value if we reverse the bytes:
    std::reverse(cv.begin(), cv.end());
    newval = 0;
    newval.import_bits(cv.begin(), cv.end(), 8, false);
    BOOST_CHECK_EQUAL(val, newval);
    // Also try importing via pointers as these may memcpy:
    newval = 0;
    newval.import_bits(cv.data(), cv.data() + cv.size(), 8, false);
    BOOST_CHECK_EQUAL(val, newval);

    cv.clear();
    val.export_bits(std::back_inserter(cv), 8, false);
    newval.import_bits(cv.begin(), cv.end(), 8, false);
    BOOST_CHECK_EQUAL(val, newval);
    std::reverse(cv.begin(), cv.end());
    newval = 0;
    newval.import_bits(cv.begin(), cv.end(), 8, true);
    BOOST_CHECK_EQUAL(val, newval);

    std::vector<boost::uintmax_t> bv;
    val.export_bits(std::back_inserter(bv),
                    std::numeric_limits<boost::uintmax_t>::digits);
    newval.import_bits(bv.begin(), bv.end());
    BOOST_CHECK_EQUAL(val, newval);
    // Should get the same value if we reverse the values:
    std::reverse(bv.begin(), bv.end());
    newval = 0;
    newval.import_bits(bv.begin(), bv.end(),
                       std::numeric_limits<boost::uintmax_t>::digits, false);
    BOOST_CHECK_EQUAL(val, newval);
    // Also try importing via pointers as these may memcpy:
    newval = 0;
    newval.import_bits(bv.data(), bv.data() + bv.size(),
                       std::numeric_limits<boost::uintmax_t>::digits, false);
    BOOST_CHECK_EQUAL(val, newval);

    bv.clear();
    val.export_bits(std::back_inserter(bv), std::numeric_limits<boost::uintmax_t>::digits,
                    false);
    newval.import_bits(bv.begin(), bv.end(),
                       std::numeric_limits<boost::uintmax_t>::digits, false);
    BOOST_CHECK_EQUAL(val, newval);
    //
    // Try with an unconventional number of bits, to model some machine with guard bits:
    //
    bv.clear();
    val.export_bits(std::back_inserter(bv),
                    std::numeric_limits<boost::uintmax_t>::digits - 3);
    newval.import_bits(bv.begin(), bv.end(),
                       std::numeric_limits<boost::uintmax_t>::digits - 3);
    BOOST_CHECK_EQUAL(val, newval);

    bv.clear();
    val.export_bits(std::back_inserter(bv),
                    std::numeric_limits<boost::uintmax_t>::digits - 3, false);
    newval.import_bits(bv.begin(), bv.end(),
                       std::numeric_limits<boost::uintmax_t>::digits - 3, false);
    BOOST_CHECK_EQUAL(val, newval);

    cv.clear();
    val.export_bits(std::back_inserter(cv), 6);
    newval.import_bits(cv.begin(), cv.end(), 6);
    BOOST_CHECK_EQUAL(val, newval);

    cv.clear();
    val.export_bits(std::back_inserter(cv), 6, false);
    newval.import_bits(cv.begin(), cv.end(), 6, false);
    BOOST_CHECK_EQUAL(val, newval);
}

template<class T>
void test_round_trip() {
    std::cout << std::hex;
    std::cerr << std::hex;
    for (unsigned i = 0; i < 1000; ++i) {
        T val = generate_random<T>();
        test_round_trip(val);
    }

    // Bug cases.
    T bug(1);
    bug << std::numeric_limits<T>::digits - 1;
    --bug;
    test_round_trip(bug);
}

BOOST_AUTO_TEST_CASE(import_export_round_trip) {
    test_round_trip<nil::crypto3::multiprecision::big_uint<130>>();
    test_round_trip<nil::crypto3::multiprecision::big_uint<256>>();
    test_round_trip<nil::crypto3::multiprecision::big_uint<298>>();
    test_round_trip<nil::crypto3::multiprecision::big_uint<512>>();
}
