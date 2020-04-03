//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE message_id

#include <nil/actor/message_id.hpp>

#include <nil/actor/test/dsl.hpp>

using namespace nil::actor;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<>
            struct print_log_value<message_id> {
                void operator()(std::ostream &, message_id const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

BOOST_AUTO_TEST_CASE(default_construction) {
    message_id x;
    BOOST_CHECK_EQUAL(x.is_async(), true);
    BOOST_CHECK_EQUAL(x.is_request(), false);
    BOOST_CHECK_EQUAL(x.is_response(), false);
    BOOST_CHECK_EQUAL(x.is_answered(), false);
    BOOST_CHECK(x.category() == message_id::normal_message_category);
    BOOST_CHECK_EQUAL(x.is_urgent_message(), false);
    BOOST_CHECK_EQUAL(x.is_normal_message(), true);
    BOOST_CHECK_EQUAL(x.is_stream_message(), false);
    BOOST_CHECK_EQUAL(x.is_upstream_message(), false);
    BOOST_CHECK_EQUAL(x.is_downstream_message(), false);
    BOOST_CHECK_EQUAL(x, x.response_id());
    BOOST_CHECK_EQUAL(x.request_id().integer_value(), 0u);
    BOOST_CHECK(x.integer_value() == message_id::default_async_value);
}

BOOST_AUTO_TEST_CASE(make_message_id_test) {
    auto x = make_message_id();
    message_id y;
    BOOST_CHECK_EQUAL(x, y);
    BOOST_CHECK_EQUAL(x.integer_value(), y.integer_value());
}

BOOST_AUTO_TEST_CASE(from_integer_value) {
    auto x = make_message_id(42);
    BOOST_CHECK_EQUAL(x.is_async(), false);
    BOOST_CHECK_EQUAL(x.is_request(), true);
    BOOST_CHECK_EQUAL(x.is_response(), false);
    BOOST_CHECK_EQUAL(x.is_answered(), false);
    BOOST_CHECK(x.category() == message_id::normal_message_category);
    BOOST_CHECK_EQUAL(x.is_urgent_message(), false);
    BOOST_CHECK_EQUAL(x.is_normal_message(), true);
    BOOST_CHECK_EQUAL(x.is_stream_message(), false);
    BOOST_CHECK_EQUAL(x.is_upstream_message(), false);
    BOOST_CHECK_EQUAL(x.is_downstream_message(), false);
    BOOST_CHECK_EQUAL(x.request_id().integer_value(), 42u);
}

BOOST_AUTO_TEST_CASE(response_id) {
    auto x = make_message_id(42).response_id();
    BOOST_CHECK_EQUAL(x.is_async(), false);
    BOOST_CHECK_EQUAL(x.is_request(), false);
    BOOST_CHECK_EQUAL(x.is_response(), true);
    BOOST_CHECK_EQUAL(x.is_answered(), false);
    BOOST_CHECK(x.category() == message_id::normal_message_category);
    BOOST_CHECK_EQUAL(x.is_urgent_message(), false);
    BOOST_CHECK_EQUAL(x.is_normal_message(), true);
    BOOST_CHECK_EQUAL(x.is_stream_message(), false);
    BOOST_CHECK_EQUAL(x.is_upstream_message(), false);
    BOOST_CHECK_EQUAL(x.is_downstream_message(), false);
    BOOST_CHECK_EQUAL(x.request_id().integer_value(), 42u);
}

BOOST_AUTO_TEST_CASE(request_with_high_priority) {
    auto x = make_message_id(42).response_id();
    BOOST_CHECK_EQUAL(x.is_async(), false);
    BOOST_CHECK_EQUAL(x.is_request(), false);
    BOOST_CHECK_EQUAL(x.is_response(), true);
    BOOST_CHECK_EQUAL(x.is_answered(), false);
    BOOST_CHECK(x.category() == message_id::normal_message_category);
    BOOST_CHECK_EQUAL(x.is_urgent_message(), false);
    BOOST_CHECK_EQUAL(x.is_normal_message(), true);
    BOOST_CHECK_EQUAL(x.is_stream_message(), false);
    BOOST_CHECK_EQUAL(x.is_upstream_message(), false);
    BOOST_CHECK_EQUAL(x.is_downstream_message(), false);
    BOOST_CHECK_EQUAL(x.request_id().integer_value(), 42u);
}

BOOST_AUTO_TEST_CASE(with_category_test) {
    auto x = make_message_id();
    BOOST_CHECK(x.category() == message_id::normal_message_category);
    for (auto category : {message_id::urgent_message_category, message_id::downstream_message_category,
                          message_id::upstream_message_category, message_id::normal_message_category}) {
        x = x.with_category(category);
        BOOST_CHECK_EQUAL(x.category(), category);
        BOOST_CHECK_EQUAL(x.is_request(), false);
        BOOST_CHECK_EQUAL(x.is_response(), false);
        BOOST_CHECK_EQUAL(x.is_answered(), false);
    }
}
