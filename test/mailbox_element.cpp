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

#define BOOST_TEST_MODULE mailbox_element_test

#include <boost/test/unit_test.hpp>

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
    optional<tuple<Ts...>> fetch(const type_erased_tuple &x) {
        if (!x.match_elements<Ts...>()) {
            return none;
        }
        return x.get_as_tuple<Ts...>();
    }

    template<class... Ts>
    optional<tuple<Ts...>> fetch(const message &x) {
        return fetch<Ts...>(x.content());
    }

    template<class... Ts>
    optional<tuple<Ts...>> fetch(const mailbox_element &x) {
        return fetch<Ts...>(x.content());
    }

}    // namespace

BOOST_AUTO_TEST_CASE(empty_message_test) {
    auto m1 = make_mailbox_element(nullptr, make_message_id(), no_stages, make_message());
    BOOST_CHECK(m1->mid.is_async());
    BOOST_CHECK(m1->mid.category() == message_id::normal_message_category);
    BOOST_CHECK(m1->content().empty());
}

BOOST_AUTO_TEST_CASE(non_empty_message_test) {
    auto m1 = make_mailbox_element(nullptr, make_message_id(), no_stages, make_message(1, 2, 3));
    BOOST_CHECK(m1->mid.is_async());
    BOOST_CHECK(m1->mid.category() == message_id::normal_message_category);
    BOOST_CHECK(!m1->content().empty());
    BOOST_CHECK((fetch<int, int>(*m1)) == none);
    BOOST_CHECK((fetch<int, int, int>(*m1)) == make_tuple(1, 2, 3));
}

BOOST_AUTO_TEST_CASE(message_roundtrip_test) {
    auto msg = make_message(1, 2, 3);
    auto msg_ptr = msg.cvals().get();
    auto m1 = make_mailbox_element(nullptr, make_message_id(), no_stages, std::move(msg));
    auto msg2 = m1->move_content_to_message();
    BOOST_CHECK_EQUAL(msg2.cvals().get(), msg_ptr);
}

BOOST_AUTO_TEST_CASE(message_roundtrip_with_copy_test) {
    auto msg = make_message(1, 2, 3);
    auto msg_ptr = msg.cvals().get();
    auto m1 = make_mailbox_element(nullptr, make_message_id(), no_stages, std::move(msg));
    auto msg2 = m1->copy_content_to_message();
    auto msg3 = m1->move_content_to_message();
    BOOST_CHECK_EQUAL(msg2.cvals().get(), msg_ptr);
    BOOST_CHECK_EQUAL(msg3.cvals().get(), msg_ptr);
}

BOOST_AUTO_TEST_CASE(tuple_test) {
    auto m1 = make_mailbox_element(nullptr, make_message_id(), no_stages, 1, 2, 3);
    BOOST_CHECK(m1->mid.is_async());
    BOOST_CHECK(m1->mid.category() == message_id::normal_message_category);
    BOOST_CHECK(!m1->content().empty());
    BOOST_CHECK((fetch<int, int>(*m1)) == none);
    BOOST_CHECK((fetch<int, int, int>(*m1)) == make_tuple(1, 2, 3));
}

BOOST_AUTO_TEST_CASE(move_tuple_test) {
    auto m1 = make_mailbox_element(nullptr, make_message_id(), no_stages, "hello", "world");
    using strings = tuple<string, string>;
    BOOST_CHECK((fetch<string, string>(*m1)) == strings("hello", "world"));
    auto msg = m1->move_content_to_message();
    BOOST_CHECK((fetch<string, string>(msg)) == strings("hello", "world"));
    BOOST_CHECK((fetch<string, string>(*m1)) == strings("", ""));
}

BOOST_AUTO_TEST_CASE(copy_tuple_test) {
    auto m1 = make_mailbox_element(nullptr, make_message_id(), no_stages, "hello", "world");
    using strings = tuple<string, string>;
    BOOST_CHECK((fetch<string, string>(*m1)) == strings("hello", "world"));
    auto msg = m1->copy_content_to_message();
    BOOST_CHECK((fetch<string, string>(msg)) == strings("hello", "world"));
    BOOST_CHECK((fetch<string, string>(*m1)) == strings("hello", "world"));
}

BOOST_AUTO_TEST_CASE(high_priority_test) {
    auto m1 = make_mailbox_element(nullptr, make_message_id(message_priority::high), no_stages, 42);
    BOOST_CHECK(m1->mid.category() == message_id::urgent_message_category);
}

BOOST_AUTO_TEST_CASE(upstream_msg_static_test) {
    auto m1 = make_mailbox_element(nullptr, make_message_id(), no_stages, make<upstream_msg::drop>({0, 0}, nullptr));
    BOOST_CHECK(m1->mid.category() == message_id::upstream_message_category);
}

BOOST_AUTO_TEST_CASE(upstream_msg_dynamic_test) {
    auto m1 = make_mailbox_element(nullptr, make_message_id(), no_stages,
                                   make_message(make<upstream_msg::drop>({0, 0}, nullptr)));
    BOOST_CHECK(m1->mid.category() == message_id::upstream_message_category);
}

BOOST_AUTO_TEST_CASE(downstream_msg_static_test) {
    auto m1 = make_mailbox_element(nullptr, make_message_id(), no_stages, make<downstream_msg::close>({0, 0}, nullptr));
    BOOST_CHECK(m1->mid.category() == message_id::downstream_message_category);
}

BOOST_AUTO_TEST_CASE(downstream_msg_dynamic_test) {
    auto m1 = make_mailbox_element(nullptr, make_message_id(), no_stages,
                                   make_message(make<downstream_msg::close>({0, 0}, nullptr)));
    BOOST_CHECK(m1->mid.category() == message_id::downstream_message_category);
}
