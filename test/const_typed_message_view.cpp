//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE const_typed_message_view

#include <nil/actor/const_typed_message_view.hpp>

#include <nil/actor/test/dsl.hpp>

#include <nil/actor/message.hpp>

using namespace nil::actor;

BOOST_FIXTURE_TEST_SUITE(message_tests, test_coordinator_fixture<>)

BOOST_AUTO_TEST_CASE(const_message_views_never_detach_their_content) {
    auto msg1 = make_message(1, 2, 3, "four");
    auto msg2 = msg1;
    BOOST_REQUIRE(msg1.cptr() == msg2.cptr());
    BOOST_REQUIRE((msg1.match_elements<int, int, int, std::string>()));
    const_typed_message_view<int, int, int, std::string> view {msg1};
    BOOST_REQUIRE(msg1.cptr() == msg2.cptr());
}

BOOST_AUTO_TEST_CASE(const_message_views_allow_access_via_get) {
    auto msg = make_message(1, 2, 3, "four");
    BOOST_REQUIRE((msg.match_elements<int, int, int, std::string>()));
    const_typed_message_view<int, int, int, std::string> view {msg};
    BOOST_CHECK_EQUAL(get<0>(view), 1);
    BOOST_CHECK_EQUAL(get<1>(view), 2);
    BOOST_CHECK_EQUAL(get<2>(view), 3);
    BOOST_CHECK_EQUAL(get<3>(view), "four");
}

BOOST_AUTO_TEST_SUITE_END()
