//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt or
// http://opensource.org/licenses/BSD-3-Clause
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE deep_to_string_test

#include <nil/actor/deep_to_string.hpp>

#include <nil/actor/test/dsl.hpp>

using namespace nil::actor;

namespace {

    void foobar() {
        // nop
    }

}    // namespace

BOOST_AUTO_TEST_CASE(timespans_test) {
    BOOST_CHECK_EQUAL(deep_to_string(timespan {1}), "1ns");
    BOOST_CHECK_EQUAL(deep_to_string(timespan {1000}), "1us");
    BOOST_CHECK_EQUAL(deep_to_string(timespan {1000000}), "1ms");
    BOOST_CHECK_EQUAL(deep_to_string(timespan {1000000000}), "1s");
    BOOST_CHECK_EQUAL(deep_to_string(timespan {60000000000}), "1min");
}

BOOST_AUTO_TEST_CASE(pointers_test) {
    auto i = 42;
    BOOST_CHECK_EQUAL(deep_to_string(&i), "*42");
    BOOST_CHECK_EQUAL(deep_to_string(foobar), "<fun>");
}