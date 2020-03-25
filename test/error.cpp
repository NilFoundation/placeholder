//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE error_test

#include <nil/actor/test/dsl.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <nil/actor/error.hpp>

using namespace nil::actor;

BOOST_AUTO_TEST_SUITE(error_test_suite)

BOOST_AUTO_TEST_CASE(default_constructed_errors_evaluate_to_false) {
    error err;
    BOOST_CHECK(!err);
}

BOOST_AUTO_TEST_CASE(error_code_zero_is_not_an_error) {
    BOOST_CHECK(!error(0, atom("system")));
    BOOST_CHECK(!make_error(sec::none));
    BOOST_CHECK(!error {error_code<sec>(sec::none)});
}

BOOST_AUTO_TEST_CASE(error_codes_that_are_not_zero_are_errors) {
    BOOST_CHECK(error(1, atom("system")));
    BOOST_CHECK(make_error(sec::unexpected_message));
    BOOST_CHECK(error {error_code<sec>(sec::unexpected_message)});
}

BOOST_AUTO_TEST_CASE(errors_convert_enums_to_their_integer_value) {
    BOOST_CHECK_EQUAL(make_error(sec::unexpected_message).code(), 1u);
    BOOST_CHECK_EQUAL(error {error_code<sec>(sec::unexpected_message)}.code(), 1u);
}

BOOST_AUTO_TEST_SUITE_END()