//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE message_lifetime_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <atomic>
#include <iostream>

#include <nil/actor/all.hpp>
#include <nil/actor/config.hpp>

using namespace nil::actor;

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
                BOOST_CHECK(dm.reason == exit_reason::normal);
                BOOST_CHECK(dm.source == aut_.address());
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

    struct fixture {
        spawner_config cfg;
        spawner system {cfg};
    };

    struct fail_on_copy {
        int value;

        fail_on_copy(int x = 0) : value(x) {
            // nop
        }

        fail_on_copy(fail_on_copy &&) = default;

        fail_on_copy &operator=(fail_on_copy &&) = default;

        fail_on_copy(const fail_on_copy &) {
            BOOST_FAIL("fail_on_copy: copy constructor called");
        }

        fail_on_copy &operator=(const fail_on_copy &) {
            BOOST_FAIL("fail_on_copy: copy assign operator called");
            return *this;
        }
    };

    template<class Inspector>
    typename Inspector::result_type inspect(Inspector &f, fail_on_copy &x) {
        return f(x.value);
    }

}    // namespace

BOOST_FIXTURE_TEST_SUITE(message_lifetime_tests, fixture)

BOOST_AUTO_TEST_CASE(nocopy_in_scoped_actor_test) {
    auto msg = make_message(fail_on_copy {1});
    scoped_actor self {system};
    self->send(self, msg);
    self->receive([&](const fail_on_copy &x) {
        BOOST_CHECK_EQUAL(x.value, 1);
        BOOST_CHECK_EQUAL(msg.cvals()->get_reference_count(), 2u);
    });
    BOOST_CHECK_EQUAL(msg.cvals()->get_reference_count(), 1u);
}

BOOST_AUTO_TEST_CASE(message_lifetime_in_scoped_actor_test) {
    auto msg = make_message(1, 2, 3);
    scoped_actor self {system};
    self->send(self, msg);
    self->receive([&](int a, int b, int c) {
        BOOST_CHECK_EQUAL(a, 1);
        BOOST_CHECK_EQUAL(b, 2);
        BOOST_CHECK_EQUAL(c, 3);
        BOOST_CHECK_EQUAL(msg.cvals()->get_reference_count(), 2u);
    });
    BOOST_CHECK_EQUAL(msg.cvals()->get_reference_count(), 1u);
    msg = make_message(42);
    self->send(self, msg);
    BOOST_CHECK_EQUAL(msg.cvals()->get_reference_count(), 2u);
    self->receive([&](int &value) {
        BOOST_CHECK_NE(&value, msg.at(0));
        value = 10;
    });
    BOOST_CHECK_EQUAL(msg.get_as<int>(0), 42);
}

BOOST_AUTO_TEST_CASE(message_lifetime_in_spawned_actor_test) {
    for (size_t i = 0; i < 100; ++i) {
        system.spawn<tester>(system.spawn<testee>());
    }
}

BOOST_AUTO_TEST_SUITE_END()
