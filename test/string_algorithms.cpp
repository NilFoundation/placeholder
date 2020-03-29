//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE string_algorithms

#include <nil/actor/string_algorithms.hpp>

#include "core-test.hpp"

#include <string>
#include <vector>

using namespace nil::actor;

namespace {

    using str_list = std::vector<std::string>;

    str_list split(string_view str) {
        str_list result;
        nil::actor::split(result, str, ",");
        return result;
    }

    str_list compressed_split(string_view str) {
        str_list result;
        nil::actor::split(result, str, ",", token_compress_on);
        return result;
    }

    std::string join(str_list vec) {
        return nil::actor::join(vec, ",");
    }

}    // namespace

BOOST_AUTO_TEST_CASE(splitting) {
    BOOST_CHECK_EQUAL(split(""), str_list({""}));
    BOOST_CHECK_EQUAL(split(","), str_list({"", ""}));
    BOOST_CHECK_EQUAL(split(",,"), str_list({"", "", ""}));
    BOOST_CHECK_EQUAL(split(",,,"), str_list({"", "", "", ""}));
    BOOST_CHECK_EQUAL(split("a,b,c"), str_list({"a", "b", "c"}));
    BOOST_CHECK_EQUAL(split("a,,b,c,"), str_list({"a", "", "b", "c", ""}));
}

BOOST_AUTO_TEST_CASE(compressed_splitting) {
    BOOST_CHECK_EQUAL(compressed_split(""), str_list({}));
    BOOST_CHECK_EQUAL(compressed_split(","), str_list({}));
    BOOST_CHECK_EQUAL(compressed_split(",,"), str_list({}));
    BOOST_CHECK_EQUAL(compressed_split(",,,"), str_list({}));
    BOOST_CHECK_EQUAL(compressed_split("a,b,c"), str_list({"a", "b", "c"}));
    BOOST_CHECK_EQUAL(compressed_split("a,,b,c,"), str_list({"a", "b", "c"}));
}

BOOST_AUTO_TEST_CASE(joining) {
    BOOST_CHECK_EQUAL(join({}), "");
    BOOST_CHECK_EQUAL(join({""}), "");
    BOOST_CHECK_EQUAL(join({"", ""}), ",");
    BOOST_CHECK_EQUAL(join({"", "", ""}), ",,");
    BOOST_CHECK_EQUAL(join({"a"}), "a");
    BOOST_CHECK_EQUAL(join({"a", "b"}), "a,b");
    BOOST_CHECK_EQUAL(join({"a", "b", "c"}), "a,b,c");
}

BOOST_AUTO_TEST_CASE(starts_with) {
    ACTOR_CHECK(starts_with("foobar", "f"));
    ACTOR_CHECK(starts_with("foobar", "fo"));
    ACTOR_CHECK(starts_with("foobar", "fooba"));
    ACTOR_CHECK(starts_with("foobar", "foobar"));
    ACTOR_CHECK(!starts_with("foobar", "o"));
    ACTOR_CHECK(!starts_with("foobar", "fa"));
    ACTOR_CHECK(!starts_with("foobar", "foobaro"));
}

BOOST_AUTO_TEST_CASE(ends_with) {
    ACTOR_CHECK(ends_with("foobar", "r"));
    ACTOR_CHECK(ends_with("foobar", "ar"));
    ACTOR_CHECK(ends_with("foobar", "oobar"));
    ACTOR_CHECK(ends_with("foobar", "foobar"));
    ACTOR_CHECK(!ends_with("foobar", "a"));
    ACTOR_CHECK(!ends_with("foobar", "car"));
    ACTOR_CHECK(!ends_with("foobar", "afoobar"));
}
