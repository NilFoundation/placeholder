//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE detail.bounds_checker

#include <nil/actor/detail/bounds_checker.hpp>

#include <nil/actor/test/dsl.hpp>

namespace {

    template<class T>
    bool check(int64_t x) {
        return nil::actor::detail::bounds_checker<T>::check(x);
    }

}    // namespace

BOOST_AUTO_TEST_CASE(small_integers) {
    BOOST_CHECK_EQUAL(check<int8_t>(128), false);
    BOOST_CHECK_EQUAL(check<int8_t>(127), true);
    BOOST_CHECK_EQUAL(check<int8_t>(-128), true);
    BOOST_CHECK_EQUAL(check<int8_t>(-129), false);
    BOOST_CHECK_EQUAL(check<uint8_t>(-1), false);
    BOOST_CHECK_EQUAL(check<uint8_t>(0), true);
    BOOST_CHECK_EQUAL(check<uint8_t>(255), true);
    BOOST_CHECK_EQUAL(check<uint8_t>(256), false);
    BOOST_CHECK_EQUAL(check<int16_t>(-32769), false);
    BOOST_CHECK_EQUAL(check<int16_t>(-32768), true);
    BOOST_CHECK_EQUAL(check<int16_t>(32767), true);
    BOOST_CHECK_EQUAL(check<int16_t>(32768), false);
    BOOST_CHECK_EQUAL(check<uint16_t>(-1), false);
    BOOST_CHECK_EQUAL(check<uint16_t>(0), true);
    BOOST_CHECK_EQUAL(check<uint16_t>(65535), true);
    BOOST_CHECK_EQUAL(check<uint16_t>(65536), false);
}

BOOST_AUTO_TEST_CASE(large_unsigned_integers) {
    BOOST_CHECK_EQUAL(check<uint64_t>(-1), false);
    BOOST_CHECK_EQUAL(check<uint64_t>(0), true);
    BOOST_CHECK_EQUAL(check<uint64_t>(std::numeric_limits<int64_t>::max()), true);
}
