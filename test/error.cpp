//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE error

#include <nil/actor/error.hpp>

#include <nil/actor/test/dsl.hpp>

using namespace nil::actor;

BOOST_AUTO_TEST_CASE(default_constructed_errors_evaluate_to_false) {
    error err;
    BOOST_CHECK(!err);
}

BOOST_AUTO_TEST_CASE(error_code_zero_is_not_an_error) {
    BOOST_CHECK(!error(0, error_category<sec>::value));
    BOOST_CHECK(!make_error(sec::none));
    BOOST_CHECK(!error {error_code<sec>(sec::none)});
}

BOOST_AUTO_TEST_CASE(error_codes_that_are_not_zero_are_errors) {
    BOOST_CHECK(error(1, error_category<sec>::value));
    BOOST_CHECK(make_error(sec::unexpected_message));
    BOOST_CHECK(error {error_code<sec>(sec::unexpected_message)});
}

BOOST_AUTO_TEST_CASE(errors_convert_enums_to_their_integer_value) {
    BOOST_CHECK_EQUAL(make_error(sec::unexpected_message).code(), 1u);
    BOOST_CHECK_EQUAL(error {error_code<sec>(sec::unexpected_message)}.code(), 1u);
}
