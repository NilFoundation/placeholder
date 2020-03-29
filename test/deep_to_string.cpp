//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE deep_to_string

#include <nil/actor/deep_to_string.hpp>

#include "core-test.hpp"

using namespace nil::actor;

namespace {

    void foobar() {
        // nop
    }

}    // namespace

#define CHECK_DEEP_TO_STRING(val, str) BOOST_CHECK_EQUAL(deep_to_string(val), str)

BOOST_AUTO_TEST_CASE(timespans) {
    CHECK_DEEP_TO_STRING(timespan {1}, "1ns");
    CHECK_DEEP_TO_STRING(timespan {1000}, "1us");
    CHECK_DEEP_TO_STRING(timespan {1000000}, "1ms");
    CHECK_DEEP_TO_STRING(timespan {1000000000}, "1s");
    CHECK_DEEP_TO_STRING(timespan {60000000000}, "1min");
}

BOOST_AUTO_TEST_CASE(integer_lists) {
    int carray[] = {1, 2, 3, 4};
    using array_type = std::array<int, 4>;
    CHECK_DEEP_TO_STRING(std::list<int>({1, 2, 3, 4}), "[1, 2, 3, 4]");
    CHECK_DEEP_TO_STRING(std::vector<int>({1, 2, 3, 4}), "[1, 2, 3, 4]");
    CHECK_DEEP_TO_STRING(std::set<int>({1, 2, 3, 4}), "[1, 2, 3, 4]");
    CHECK_DEEP_TO_STRING(array_type({{1, 2, 3, 4}}), "[1, 2, 3, 4]");
    CHECK_DEEP_TO_STRING(carray, "[1, 2, 3, 4]");
}

BOOST_AUTO_TEST_CASE(boolean_lists) {
    bool carray[] = {false, true};
    using array_type = std::array<bool, 2>;
    CHECK_DEEP_TO_STRING(std::list<bool>({false, true}), "[false, true]");
    CHECK_DEEP_TO_STRING(std::vector<bool>({false, true}), "[false, true]");
    CHECK_DEEP_TO_STRING(std::set<bool>({false, true}), "[false, true]");
    CHECK_DEEP_TO_STRING(array_type({{false, true}}), "[false, true]");
    CHECK_DEEP_TO_STRING(carray, "[false, true]");
}

BOOST_AUTO_TEST_CASE(pointers) {
    auto i = 42;
    CHECK_DEEP_TO_STRING(&i, "*42");
    CHECK_DEEP_TO_STRING(foobar, "<fun>");
}

BOOST_AUTO_TEST_CASE(buffers) {
    // Use `signed char` explicitly to make sure all compilers agree.
    std::vector<signed char> buf;
    BOOST_CHECK_EQUAL(deep_to_string(buf), "[]");
    BOOST_CHECK_EQUAL(deep_to_string(meta::hex_formatted(), buf), "00");
    buf.push_back(-1);
    BOOST_CHECK_EQUAL(deep_to_string(buf), "[-1]");
    BOOST_CHECK_EQUAL(deep_to_string(meta::hex_formatted(), buf), "FF");
    buf.push_back(0);
    BOOST_CHECK_EQUAL(deep_to_string(buf), "[-1, 0]");
    BOOST_CHECK_EQUAL(deep_to_string(meta::hex_formatted(), buf), "FF00");
    buf.push_back(127);
    BOOST_CHECK_EQUAL(deep_to_string(buf), "[-1, 0, 127]");
    BOOST_CHECK_EQUAL(deep_to_string(meta::hex_formatted(), buf), "FF007F");
    buf.push_back(10);
    BOOST_CHECK_EQUAL(deep_to_string(buf), "[-1, 0, 127, 10]");
    BOOST_CHECK_EQUAL(deep_to_string(meta::hex_formatted(), buf), "FF007F0A");
    buf.push_back(16);
    BOOST_CHECK_EQUAL(deep_to_string(buf), "[-1, 0, 127, 10, 16]");
    BOOST_CHECK_EQUAL(deep_to_string(meta::hex_formatted(), buf), "FF007F0A10");
}
