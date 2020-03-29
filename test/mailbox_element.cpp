//---------------------------------------------------------------------------//
// Copyright (c) 2011-2017 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE mailbox_element

#include <nil/actor/mailbox_element.hpp>

#include "core-test.hpp"

#include <string>
#include <tuple>
#include <vector>

#include <nil/actor/all.hpp>

using std::make_tuple;
using std::string;
using std::tuple;
using std::vector;

using namespace nil::actor;

namespace {

    template<class... Ts>
    optional<tuple<Ts...>> fetch(const message &x) {
        if (auto view = make_const_typed_message_view<Ts...>(x))
            return to_tuple(view);
        return none;
    }

    template<class... Ts>
    optional<tuple<Ts...>> fetch(const mailbox_element &x) {
        return fetch<Ts...>(x.content());
    }

}    // namespace

BOOST_AUTO_TEST_CASE(empty_message) {
    auto m1 = make_mailbox_element(nullptr, make_message_id(), no_stages, make_message());
    ACTOR_CHECK(m1->mid.is_async());
    ACTOR_CHECK(m1->mid.category() == message_id::normal_message_category);
    ACTOR_CHECK(m1->content().empty());
}

BOOST_AUTO_TEST_CASE(non_empty_message) {
    auto m1 = make_mailbox_element(nullptr, make_message_id(), no_stages, make_message(1, 2, 3));
    ACTOR_CHECK(m1->mid.is_async());
    ACTOR_CHECK(m1->mid.category() == message_id::normal_message_category);
    ACTOR_CHECK(!m1->content().empty());
    BOOST_CHECK_EQUAL((fetch<int, int>(*m1)), none);
    BOOST_CHECK_EQUAL((fetch<int, int, int>(*m1)), make_tuple(1, 2, 3));
}

BOOST_AUTO_TEST_CASE(tuple) {
    auto m1 = make_mailbox_element(nullptr, make_message_id(), no_stages, 1, 2, 3);
    ACTOR_CHECK(m1->mid.is_async());
    ACTOR_CHECK(m1->mid.category() == message_id::normal_message_category);
    ACTOR_CHECK(!m1->content().empty());
    BOOST_CHECK_EQUAL((fetch<int, int>(*m1)), none);
    BOOST_CHECK_EQUAL((fetch<int, int, int>(*m1)), make_tuple(1, 2, 3));
}

BOOST_AUTO_TEST_CASE(high_priority) {
    auto m1 = make_mailbox_element(nullptr, make_message_id(message_priority::high), no_stages, 42);
    ACTOR_CHECK(m1->mid.category() == message_id::urgent_message_category);
}

BOOST_AUTO_TEST_CASE(upstream_msg_static) {
    auto m1 = make_mailbox_element(nullptr, make_message_id(), no_stages, make<upstream_msg::drop>({0, 0}, nullptr));
    ACTOR_CHECK(m1->mid.category() == message_id::upstream_message_category);
}

BOOST_AUTO_TEST_CASE(upstream_msg_dynamic) {
    auto m1 = make_mailbox_element(nullptr, make_message_id(), no_stages,
                                   make_message(make<upstream_msg::drop>({0, 0}, nullptr)));
    ACTOR_CHECK(m1->mid.category() == message_id::upstream_message_category);
}

BOOST_AUTO_TEST_CASE(downstream_msg_static) {
    auto m1 = make_mailbox_element(nullptr, make_message_id(), no_stages, make<downstream_msg::close>({0, 0}, nullptr));
    ACTOR_CHECK(m1->mid.category() == message_id::downstream_message_category);
}

BOOST_AUTO_TEST_CASE(downstream_msg_dynamic) {
    auto m1 = make_mailbox_element(nullptr, make_message_id(), no_stages,
                                   make_message(make<downstream_msg::close>({0, 0}, nullptr)));
    ACTOR_CHECK(m1->mid.category() == message_id::downstream_message_category);
}
