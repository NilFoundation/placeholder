//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE string_view

#include <nil/actor/string_view.hpp>

#include <nil/actor/test/dsl.hpp>

using namespace nil::actor;

BOOST_AUTO_TEST_CASE(default_construction) {
    string_view x;
    string_view y;
    BOOST_CHECK(x.empty());
    BOOST_CHECK_EQUAL(x.size(), 0u);
    BOOST_CHECK_EQUAL(x.data(), nullptr);
    BOOST_CHECK_EQUAL(y, y);
}

BOOST_AUTO_TEST_CASE(cstring_conversion) {
    string_view x = "abc";
    BOOST_CHECK_EQUAL(x.size(), 3u);
    BOOST_CHECK_EQUAL(x[0], 'a');
    BOOST_CHECK_EQUAL(x[1], 'b');
    BOOST_CHECK_EQUAL(x[2], 'c');
    BOOST_CHECK_EQUAL(x, "abc");
    x = "def";
    BOOST_CHECK_NE(x, "abc");
    BOOST_CHECK_EQUAL(x, "def");
}

BOOST_AUTO_TEST_CASE(string_conversion) {
    std::string x = "abc";
    string_view y;
    y = x;
    BOOST_CHECK_EQUAL(x, y);
    auto f = [&](string_view z) { BOOST_CHECK_EQUAL(x, z); };
    f(x);
}

BOOST_AUTO_TEST_CASE(substrings) {
    string_view x = "abcdefghi";
    x.remove_prefix(3);
    BOOST_CHECK_EQUAL(x, "defghi");
    x = "abcdefghi";
    x.remove_suffix(3);
    BOOST_CHECK_EQUAL(x, "abcdef");
    BOOST_CHECK_EQUAL(x.substr(3, 3), "def");
    x.remove_prefix(9);
    BOOST_CHECK_EQUAL(x, "");
    x.remove_prefix(9);
    BOOST_CHECK_EQUAL(x, "");
    BOOST_CHECK_EQUAL(x.substr(9), "");
    BOOST_CHECK_EQUAL(x.substr(0, 0), "");
}

BOOST_AUTO_TEST_CASE(compare) {
    // testees
    string_view x = "abc";
    string_view y = "bcd";
    string_view z = "cde";
    // x.compare full strings
    BOOST_CHECK(x.compare("abc") == 0);
    BOOST_CHECK(x.compare(y) < 0);
    BOOST_CHECK(x.compare(z) < 0);
    // y.compare full strings
    BOOST_CHECK(y.compare(x) > 0);
    BOOST_CHECK(y.compare("bcd") == 0);
    BOOST_CHECK(y.compare(z) < 0);
    // z.compare full strings
    BOOST_CHECK(z.compare(x) > 0);
    BOOST_CHECK(z.compare(y) > 0);
    BOOST_CHECK(z.compare("cde") == 0);
    // x.compare substrings
    BOOST_CHECK(x.compare(0, 3, "abc") == 0);
    BOOST_CHECK(x.compare(1, 2, y, 0, 2) == 0);
    BOOST_CHECK(x.compare(2, 1, z, 0, 1) == 0);
    BOOST_CHECK(x.compare(2, 1, z, 0, 1) == 0);
    // make sure substrings aren't equal
    BOOST_CHECK(string_view("a/") != string_view("a/b"));
}

BOOST_AUTO_TEST_CASE(copy) {
    char buf[10];
    string_view str = "hello";
    auto n = str.copy(buf, str.size());
    BOOST_CHECK_EQUAL(n, 5u);
    buf[n] = '\0';
    BOOST_CHECK_EQUAL(str, string_view(buf, n));
    BOOST_CHECK(strcmp("hello", buf) == 0);
    n = str.copy(buf, 10, 3);
    buf[n] = '\0';
    BOOST_CHECK_EQUAL(string_view(buf, n), "lo");
    BOOST_CHECK(strcmp("lo", buf) == 0);
}

BOOST_AUTO_TEST_CASE(find) {
    // Check whether string_view behaves exactly like std::string.
    string_view x = "abcdef";
    std::string y = "abcdef";
    BOOST_CHECK_EQUAL(x.find('a'), y.find('a'));
    BOOST_CHECK_EQUAL(x.find('b'), y.find('b'));
    BOOST_CHECK_EQUAL(x.find('g'), y.find('g'));
    BOOST_CHECK_EQUAL(x.find('a', 1), y.find('a', 1));
    BOOST_CHECK_EQUAL(x.find("a"), y.find("a"));
    BOOST_CHECK_EQUAL(x.find("bc"), y.find("bc"));
    BOOST_CHECK_EQUAL(x.find("ce"), y.find("ce"));
    BOOST_CHECK_EQUAL(x.find("bc", 1), y.find("bc", 1));
    BOOST_CHECK_EQUAL(x.find("bc", 1, 0), y.find("bc", 1, 0));
    BOOST_CHECK_EQUAL(x.find("bc", 0, 1), y.find("bc", 0, 1));
    BOOST_CHECK_EQUAL(x.find("bc", 2, 2), y.find("bc", 2, 2));
}

BOOST_AUTO_TEST_CASE(rfind) {
    // Check whether string_view behaves exactly like std::string.
    string_view x = "abccba";
    std::string y = "abccba";
    BOOST_CHECK_EQUAL(x.rfind('a'), y.rfind('a'));
    BOOST_CHECK_EQUAL(x.rfind('b'), y.rfind('b'));
    BOOST_CHECK_EQUAL(x.rfind('g'), y.rfind('g'));
    BOOST_CHECK_EQUAL(x.rfind('a', 1), y.rfind('a', 1));
    BOOST_CHECK_EQUAL(x.rfind("a"), y.rfind("a"));
    BOOST_CHECK_EQUAL(x.rfind("bc"), y.rfind("bc"));
    BOOST_CHECK_EQUAL(x.rfind("ce"), y.rfind("ce"));
    BOOST_CHECK_EQUAL(x.rfind("bc", 1), y.rfind("bc", 1));
    BOOST_CHECK_EQUAL(x.rfind("bc", 1, 0), y.rfind("bc", 1, 0));
    BOOST_CHECK_EQUAL(x.rfind("bc", 0, 1), y.rfind("bc", 0, 1));
    BOOST_CHECK_EQUAL(x.rfind("bc", 2, 2), y.rfind("bc", 2, 2));
}

BOOST_AUTO_TEST_CASE(find_first_of) {
    // Check whether string_view behaves exactly like std::string.
    string_view x = "abcdef";
    std::string y = "abcdef";
    BOOST_CHECK_EQUAL(x.find_first_of('a'), y.find_first_of('a'));
    BOOST_CHECK_EQUAL(x.find_first_of('b'), y.find_first_of('b'));
    BOOST_CHECK_EQUAL(x.find_first_of('g'), y.find_first_of('g'));
    BOOST_CHECK_EQUAL(x.find_first_of('a', 1), y.find_first_of('a', 1));
    BOOST_CHECK_EQUAL(x.find_first_of("a"), y.find_first_of("a"));
    BOOST_CHECK_EQUAL(x.find_first_of("bc"), y.find_first_of("bc"));
    BOOST_CHECK_EQUAL(x.find_first_of("ce"), y.find_first_of("ce"));
    BOOST_CHECK_EQUAL(x.find_first_of("bc", 1), y.find_first_of("bc", 1));
    BOOST_CHECK_EQUAL(x.find_first_of("bc", 1, 0), y.find_first_of("bc", 1, 0));
    BOOST_CHECK_EQUAL(x.find_first_of("bc", 0, 1), y.find_first_of("bc", 0, 1));
    BOOST_CHECK_EQUAL(x.find_first_of("bc", 2, 2), y.find_first_of("bc", 2, 2));
}

BOOST_AUTO_TEST_CASE(find_last_of) {
    // Check whether string_view behaves exactly like std::string.
    string_view x = "abcdef";
    std::string y = "abcdef";
    BOOST_CHECK_EQUAL(x.find_last_of('a'), y.find_last_of('a'));
    BOOST_CHECK_EQUAL(x.find_last_of('b'), y.find_last_of('b'));
    BOOST_CHECK_EQUAL(x.find_last_of('g'), y.find_last_of('g'));
    BOOST_CHECK_EQUAL(x.find_last_of('a', 1), y.find_last_of('a', 1));
    BOOST_CHECK_EQUAL(x.find_last_of("a"), y.find_last_of("a"));
    BOOST_CHECK_EQUAL(x.find_last_of("bc"), y.find_last_of("bc"));
    BOOST_CHECK_EQUAL(x.find_last_of("ce"), y.find_last_of("ce"));
    BOOST_CHECK_EQUAL(x.find_last_of("bc", 1), y.find_last_of("bc", 1));
    BOOST_CHECK_EQUAL(x.find_last_of("bc", 1, 0), y.find_last_of("bc", 1, 0));
    BOOST_CHECK_EQUAL(x.find_last_of("bc", 0, 1), y.find_last_of("bc", 0, 1));
    BOOST_CHECK_EQUAL(x.find_last_of("bc", 2, 2), y.find_last_of("bc", 2, 2));
}

BOOST_AUTO_TEST_CASE(find_first_not_of) {
    // Check whether string_view behaves exactly like std::string.
    string_view x = "abcdef";
    std::string y = "abcdef";
    BOOST_CHECK_EQUAL(x.find_first_not_of('a'), y.find_first_not_of('a'));
    BOOST_CHECK_EQUAL(x.find_first_not_of('b'), y.find_first_not_of('b'));
    BOOST_CHECK_EQUAL(x.find_first_not_of('g'), y.find_first_not_of('g'));
    BOOST_CHECK_EQUAL(x.find_first_not_of('a', 1), y.find_first_not_of('a', 1));
    BOOST_CHECK_EQUAL(x.find_first_not_of("a"), y.find_first_not_of("a"));
    BOOST_CHECK_EQUAL(x.find_first_not_of("bc"), y.find_first_not_of("bc"));
    BOOST_CHECK_EQUAL(x.find_first_not_of("ce"), y.find_first_not_of("ce"));
    BOOST_CHECK_EQUAL(x.find_first_not_of("bc", 1), y.find_first_not_of("bc", 1));
    BOOST_CHECK_EQUAL(x.find_first_not_of("bc", 1, 0), y.find_first_not_of("bc", 1, 0));
    BOOST_CHECK_EQUAL(x.find_first_not_of("bc", 0, 1), y.find_first_not_of("bc", 0, 1));
    BOOST_CHECK_EQUAL(x.find_first_not_of("bc", 2, 2), y.find_first_not_of("bc", 2, 2));
}

BOOST_AUTO_TEST_CASE(find_last_not_of) {
    // Check whether string_view behaves exactly like std::string.
    string_view x = "abcdef";
    std::string y = "abcdef";
    BOOST_CHECK_EQUAL(x.find_last_not_of('a'), y.find_last_not_of('a'));
    BOOST_CHECK_EQUAL(x.find_last_not_of('b'), y.find_last_not_of('b'));
    BOOST_CHECK_EQUAL(x.find_last_not_of('g'), y.find_last_not_of('g'));
    BOOST_CHECK_EQUAL(x.find_last_not_of('a', 1), y.find_last_not_of('a', 1));
    BOOST_CHECK_EQUAL(x.find_last_not_of("a"), y.find_last_not_of("a"));
    BOOST_CHECK_EQUAL(x.find_last_not_of("bc"), y.find_last_not_of("bc"));
    BOOST_CHECK_EQUAL(x.find_last_not_of("ce"), y.find_last_not_of("ce"));
    BOOST_CHECK_EQUAL(x.find_last_not_of("bc", 1), y.find_last_not_of("bc", 1));
    BOOST_CHECK_EQUAL(x.find_last_not_of("bc", 1, 0), y.find_last_not_of("bc", 1, 0));
    BOOST_CHECK_EQUAL(x.find_last_not_of("bc", 0, 1), y.find_last_not_of("bc", 0, 1));
    BOOST_CHECK_EQUAL(x.find_last_not_of("bc", 2, 2), y.find_last_not_of("bc", 2, 2));
}
