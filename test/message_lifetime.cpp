//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE message_lifetime

#include "core_test.hpp"

#include <atomic>
#include <iostream>

#include <nil/actor/all.hpp>

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<>
            struct print_log_value<nil::actor::error> {
                void operator()(std::ostream &, nil::actor::error const &) {
                }
            };

            template<>
            struct print_log_value<nil::actor::exit_reason> {
                void operator()(std::ostream &, nil::actor::exit_reason const &) {
                }
            };

            template<>
            struct print_log_value<nil::actor::actor_addr> {
                void operator()(std::ostream &, nil::actor::actor_addr const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

using namespace nil::actor;

fail_on_copy::fail_on_copy(const fail_on_copy &) {
    BOOST_FAIL("fail_on_copy: copy constructor called");
}

fail_on_copy &fail_on_copy::operator=(const fail_on_copy &) {
    BOOST_FAIL("fail_on_copy: copy assign operator called");
}

namespace {

    class testee : public event_based_actor {
    public:
        testee(actor_config &cfg) : event_based_actor(cfg) {
            // nop
        }

        ~testee() override {
            // nop
        }

        behavior make_behavior() override {
            // reflecting a message increases its reference count by one
            set_default_handler(reflect_and_quit);
            return {[] {
                // nop
            }};
        }
    };

    class tester : public event_based_actor {
    public:
        tester(actor_config &cfg, actor aut) :
            event_based_actor(cfg), aut_(std::move(aut)), msg_(make_message(1, 2, 3)) {
            set_down_handler([=](down_msg &dm) {
                BOOST_CHECK_EQUAL(dm.reason, exit_reason::normal);
                BOOST_CHECK_EQUAL(dm.source, aut_.address());
                quit();
            });
        }

        behavior make_behavior() override {
            monitor(aut_);
            send(aut_, msg_);
            return {[=](int a, int b, int c) {
                BOOST_CHECK_EQUAL(a, 1);
                BOOST_CHECK_EQUAL(b, 2);
                BOOST_CHECK_EQUAL(c, 3);
            }};
        }

    private:
        actor aut_;
        message msg_;
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(message_lifetime_tests, test_coordinator_fixture<>)

BOOST_AUTO_TEST_CASE(nocopy_in_scoped_actor) {
    auto msg = make_message(fail_on_copy {1});
    self->send(self, msg);
    self->receive([&](const fail_on_copy &x) {
        BOOST_CHECK_EQUAL(x.value, 1);
        BOOST_CHECK_EQUAL(msg.cdata().get_reference_count(), 2u);
    });
    BOOST_CHECK_EQUAL(msg.cdata().get_reference_count(), 1u);
}

BOOST_AUTO_TEST_CASE(message_lifetime_in_scoped_actor) {
    auto msg = make_message(1, 2, 3);
    self->send(self, msg);
    self->receive([&](int a, int b, int c) {
        BOOST_CHECK_EQUAL(a, 1);
        BOOST_CHECK_EQUAL(b, 2);
        BOOST_CHECK_EQUAL(c, 3);
        BOOST_CHECK_EQUAL(msg.cdata().get_reference_count(), 2u);
    });
    BOOST_CHECK_EQUAL(msg.cdata().get_reference_count(), 1u);
    msg = make_message(42);
    self->send(self, msg);
    BOOST_CHECK_EQUAL(msg.cdata().get_reference_count(), 2u);
    self->receive([&](int &value) {
//        BOOST_CHECK_NE(&value, msg.cdata().at(0));
        value = 10;
    });
    BOOST_CHECK_EQUAL(msg.get_as<int>(0), 42);
}

BOOST_AUTO_TEST_CASE(message_lifetime_in_spawned_actor) {
    for (size_t i = 0; i < 100; ++i)
        sys.spawn<tester>(sys.spawn<testee>());
}

BOOST_AUTO_TEST_SUITE_END()
