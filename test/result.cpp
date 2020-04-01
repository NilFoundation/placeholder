//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE result

#include <nil/actor/test/dsl.hpp>

#include <nil/actor/sec.hpp>
#include <nil/actor/result.hpp>

using namespace std;
using namespace nil::actor;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<>
            struct print_log_value<error> {
                void operator()(std::ostream &, error const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

namespace {

    template<class T>
    void test_unit_void() {
        auto x = result<T> {};
        BOOST_CHECK_EQUAL(x.flag, rt_value);
        x = skip();
        BOOST_CHECK_EQUAL(x.flag, rt_skip);
        x = expected<T> {};
        BOOST_CHECK_EQUAL(x.flag, rt_value);
        x = expected<T> {sec::unexpected_message};
        BOOST_CHECK_EQUAL(x.flag, rt_error);
        BOOST_CHECK_EQUAL(x.err, make_error(sec::unexpected_message));
    }

}    // namespace

BOOST_AUTO_TEST_CASE(skip_test) {
    auto x = result<> {skip()};
    BOOST_CHECK_EQUAL(x.flag, rt_skip);
    BOOST_CHECK(x.value.empty());
}

BOOST_AUTO_TEST_CASE(value_test) {
    auto x = result<int> {42};
    BOOST_CHECK_EQUAL(x.flag, rt_value);
    BOOST_CHECK_EQUAL(x.value.get_as<int>(0), 42);
}

BOOST_AUTO_TEST_CASE(expected_test) {
    auto x = result<int> {expected<int> {42}};
    BOOST_CHECK_EQUAL(x.flag, rt_value);
    BOOST_CHECK_EQUAL(x.value.get_as<int>(0), 42);
    x = expected<int> {sec::unexpected_message};
    BOOST_CHECK_EQUAL(x.flag, rt_error);
    BOOST_CHECK_EQUAL(x.err, make_error(sec::unexpected_message));
    BOOST_CHECK(x.value.empty());
}

BOOST_AUTO_TEST_CASE(void_specialization) {
    test_unit_void<void>();
}

BOOST_AUTO_TEST_CASE(unit_specialization) {
    test_unit_void<unit_t>();
}
