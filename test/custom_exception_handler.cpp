//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt or
// http://opensource.org/licenses/BSD-3-Clause
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE custom_exception_handler_test

#include <boost/test/unit_test.hpp>

#include <nil/actor/all.hpp>
#include <nil/actor/config.hpp>

using namespace nil::actor;

#ifndef ACTOR_NO_EXCEPTIONS

class exception_testee : public event_based_actor {
public:
    ~exception_testee() override;

    exception_testee(actor_config &cfg) : event_based_actor(cfg) {
        set_exception_handler([](std::exception_ptr &) -> error { return exit_reason::remote_link_unreachable; });
    }

    behavior make_behavior() override {
        return {[](const std::string &) { throw std::runtime_error("whatever"); }};
    }
};

exception_testee::~exception_testee() {
    // avoid weak-vtables warning
}

BOOST_AUTO_TEST_CASE(test_custom_exception_handler_test) {
    spawner_config cfg;
    spawner system {cfg};
    auto handler = [](std::exception_ptr &eptr) -> error {
        try {
            std::rethrow_exception(eptr);
        } catch (std::runtime_error &) {
            return exit_reason::normal;
        } catch (...) {
            // "fall through"
        }
        return exit_reason::unhandled_exception;
    };
    scoped_actor self {system};
    auto testee1 = self->spawn<monitored>([=](event_based_actor *eb_self) {
        eb_self->set_exception_handler(handler);
        throw std::runtime_error("ping");
    });
    auto testee2 = self->spawn<monitored>([=](event_based_actor *eb_self) {
        eb_self->set_exception_handler(handler);
        throw std::logic_error("pong");
    });
    auto testee3 = self->spawn<exception_testee, monitored>();
    self->send(testee3, "foo");
    // receive all down messages
    self->wait_for(testee1, testee2, testee3);
}

#else    // ACTOR_NO_EXCEPTIONS

BOOST_AUTO_TEST_CASE(no_exceptions_dummy_test) {
    BOOST_CHECK_EQUAL(true, true);
}

#endif    // ACTOR_NO_EXCEPTIONS
