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

#include <nil/actor/config.hpp>

// exclude this suite; seems to be too much to swallow for MSVC
#ifndef ACTOR_WINDOWS

#define BOOST_TEST_MODULE typed_spawn_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <nil/actor/string_algorithms.hpp>
#include <nil/actor/all.hpp>

#define ERROR_HANDLER [&](error &err) { BOOST_FAIL(system.render(err)); }

using namespace nil::actor;

using passed_atom = nil::actor::atom_constant<nil::actor::atom("passed")>;

namespace {

    enum class mock_errc : uint8_t { cannot_revert_empty = 1 };

    error make_error(mock_errc x) {
        return {static_cast<uint8_t>(x), atom("mock")};
    }

    // check invariants of type system
    using dummy1 = typed_actor<reacts_to<int, int>, replies_to<double>::with<double>>;

    using dummy2 = dummy1::extend<reacts_to<ok_atom>>;

    static_assert(std::is_convertible<dummy2, dummy1>::value, "handle not assignable to narrower definition");

    // static_assert(!std::is_convertible<dummy1, dummy2>::value,
    //              "handle is assignable to broader definition");

    using dummy3 = typed_actor<reacts_to<float, int>>;
    using dummy4 = typed_actor<replies_to<int>::with<double>>;
    using dummy5 = dummy4::extend_with<dummy3>;

    static_assert(std::is_convertible<dummy5, dummy3>::value, "handle not assignable to narrower definition");

    static_assert(std::is_convertible<dummy5, dummy4>::value, "handle not assignable to narrower definition");

    // static_assert(!std::is_convertible<dummy3, dummy5>::value,
    //              "handle is assignable to broader definition");

    // static_assert(!std::is_convertible<dummy4, dummy5>::value,
    //              "handle is assignable to broader definition");

    /******************************************************************************
     *                        simple request/response test                        *
     ******************************************************************************/

    struct my_request {
        int a;
        int b;
    };

    template<class Inspector>
    typename Inspector::result_type inspect(Inspector &f, my_request &x) {
        return f(x.a, x.b);
    }

    using server_type = typed_actor<replies_to<my_request>::with<bool>>;

    server_type::behavior_type typed_server1() {
        return {[](const my_request &req) { return req.a == req.b; }};
    }

    server_type::behavior_type typed_server2(server_type::pointer) {
        return typed_server1();
    }

    class typed_server3 : public server_type::base {
    public:
        typed_server3(actor_config &cfg, const std::string &line, const actor &buddy) : server_type::base(cfg) {
            anon_send(buddy, line);
        }

        behavior_type make_behavior() override {
            return typed_server2(this);
        }
    };

    void client(event_based_actor *self, const actor &parent, const server_type &serv) {
        self->request(serv, infinite, my_request {0, 0}).then([=](bool val1) {
            BOOST_CHECK_EQUAL(val1, true);
            self->request(serv, infinite, my_request {10, 20}).then([=](bool val2) {
                BOOST_CHECK_EQUAL(val2, false);
                self->send(parent, passed_atom::value);
            });
        });
    }

    /******************************************************************************
     *          test skipping of messages intentionally + using become()          *
     ******************************************************************************/

    struct get_state_msg {};

    using event_testee_type = typed_actor<replies_to<get_state_msg>::with<std::string>,
                                          replies_to<std::string>::with<void>,
                                          replies_to<float>::with<void>,
                                          replies_to<int>::with<int>>;

    class event_testee : public event_testee_type::base {
    public:
        event_testee(actor_config &cfg) : event_testee_type::base(cfg) {
            // nop
        }

        behavior_type wait4string() {
            return {[](const get_state_msg &) { return "wait4string"; },
                    [=](const std::string &) { become(wait4int()); }, [](float) { return skip(); },
                    [](int) { return skip(); }};
        }

        behavior_type wait4int() {
            return {[](const get_state_msg &) { return "wait4int"; },
                    [=](int) -> int {
                        become(wait4float());
                        return 42;
                    },
                    [](float) { return skip(); }, [](const std::string &) { return skip(); }};
        }

        behavior_type wait4float() {
            return {[](const get_state_msg &) { return "wait4float"; }, [=](float) { become(wait4string()); },
                    [](const std::string &) { return skip(); }, [](int) { return skip(); }};
        }

        behavior_type make_behavior() override {
            return wait4int();
        }
    };

    /******************************************************************************
     *                         simple 'forwarding' chain                          *
     ******************************************************************************/

    using string_actor = typed_actor<replies_to<std::string>::with<std::string>>;

    string_actor::behavior_type string_reverter() {
        return {[](std::string &str) -> std::string {
            std::reverse(str.begin(), str.end());
            return std::move(str);
        }};
    }

    // uses `return delegate(...)`
    string_actor::behavior_type string_delegator(string_actor::pointer self, string_actor master, bool leaf) {
        auto next = leaf ? self->spawn(string_delegator, master, false) : master;
        self->link_to(next);
        return {[=](std::string &str) -> delegated<std::string> { return self->delegate(next, std::move(str)); }};
    }

    using maybe_string_actor = typed_actor<replies_to<std::string>::with<ok_atom, std::string>>;

    maybe_string_actor::behavior_type maybe_string_reverter() {
        return {[](std::string &str) -> result<ok_atom, std::string> {
            if (str.empty()) {
                return mock_errc::cannot_revert_empty;
            }
            std::reverse(str.begin(), str.end());
            return {ok_atom::value, std::move(str)};
        }};
    }

    maybe_string_actor::behavior_type maybe_string_delegator(maybe_string_actor::pointer self,
                                                             const maybe_string_actor &x) {
        self->link_to(x);
        return {[=](std::string &s) -> delegated<ok_atom, std::string> { return self->delegate(x, std::move(s)); }};
    }

    /******************************************************************************
     *                        sending typed actor handles                         *
     ******************************************************************************/

    using int_actor = typed_actor<replies_to<int>::with<int>>;

    using float_actor = typed_actor<reacts_to<float>>;

    int_actor::behavior_type int_fun() {
        return {[](int i) { return i * i; }};
    }

    behavior foo(event_based_actor *self) {
        return {[=](int i, int_actor server) {
            self->delegate(server, i);
            self->quit();
        }};
    }

    int_actor::behavior_type int_fun2(int_actor::pointer self) {
        self->set_down_handler([=](down_msg &dm) {
            BOOST_CHECK(dm.reason == exit_reason::normal);
            self->quit();
        });
        return {
            [=](int i) {
                self->monitor(self->current_sender());
                return i * i;
            },
        };
    }

    behavior foo2(event_based_actor *self) {
        return {[=](int i, int_actor server) {
            self->delegate(server, i);
            self->quit();
        }};
    }

    float_actor::behavior_type float_fun(float_actor::pointer self) {
        return {[=](float a) {
            BOOST_CHECK_EQUAL(a, 1.0f);
            self->quit(exit_reason::user_shutdown);
        }};
    }

    int_actor::behavior_type foo3(int_actor::pointer self) {
        auto b = self->spawn<linked>(float_fun);
        self->send(b, 1.0f);
        return {[=](int) { return 0; }};
    }

    struct fixture {
        spawner_config cfg;
        spawner system;
        scoped_actor self;

        static spawner_config &init(spawner_config &cfg) {
            cfg.add_message_type<get_state_msg>("get_state_msg");
            return cfg;
        }

        fixture() : system(init(cfg)), self(system) {
            // nop
        }

        void test_typed_spawn(server_type ts) {
            self->send(ts, my_request {1, 2});
            self->receive([](bool value) { BOOST_CHECK_EQUAL(value, false); });
            BOOST_TEST_MESSAGE("async send + receive");
            self->send(ts, my_request {42, 42});
            self->receive([](bool value) { BOOST_CHECK_EQUAL(value, true); });
            BOOST_TEST_MESSAGE("request + receive with result true");
            self->request(ts, infinite, my_request {10, 20})
                .receive([](bool value) { BOOST_CHECK_EQUAL(value, false); }, ERROR_HANDLER);
            BOOST_TEST_MESSAGE("request + receive with result false");
            self->request(ts, infinite, my_request {0, 0})
                .receive([](bool value) { BOOST_CHECK_EQUAL(value, true); }, ERROR_HANDLER);
            BOOST_CHECK_EQUAL(system.registry().running(), 2u);
            auto c1 = self->spawn(client, self, ts);
            self->receive([](passed_atom) { BOOST_TEST_MESSAGE("received `passed_atom`"); });
            self->wait_for(c1);
            BOOST_CHECK_EQUAL(system.registry().running(), 2u);
        }
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(typed_spawn_tests, fixture)

/******************************************************************************
 *                             put it all together                            *
 ******************************************************************************/

BOOST_AUTO_TEST_CASE(typed_spawns_test) {
    BOOST_TEST_MESSAGE("run test series with typed_server1");
    test_typed_spawn(system.spawn(typed_server1));
    self->await_all_other_actors_done();
    BOOST_TEST_MESSAGE("finished test series with `typed_server1`");
    BOOST_TEST_MESSAGE("run test series with typed_server2");
    test_typed_spawn(system.spawn(typed_server2));
    self->await_all_other_actors_done();
    BOOST_TEST_MESSAGE("finished test series with `typed_server2`");
    test_typed_spawn(self->spawn<typed_server3>("hi there", self));
    self->receive([](const std::string &str) { BOOST_REQUIRE_EQUAL(str, "hi there"); });
}

BOOST_AUTO_TEST_CASE(event_testee_series_test) {
    auto et = self->spawn<event_testee>();
    std::string result;
    self->send(et, 1);
    self->send(et, 2);
    self->send(et, 3);
    self->send(et, .1f);
    self->send(et, "hello event testee!");
    self->send(et, .2f);
    self->send(et, .3f);
    self->send(et, "hello again event testee!");
    self->send(et, "goodbye event testee!");
    typed_actor<replies_to<get_state_msg>::with<std::string>> sub_et = et;
    std::set<std::string> iface {"nil::actor::replies_to<get_state_msg>::with<@str>",
                                 "nil::actor::replies_to<@str>::with<void>", "nil::actor::replies_to<float>::with<void>",
                                 "nil::actor::replies_to<@i32>::with<@i32>"};
    BOOST_CHECK_EQUAL(join(sub_et->message_types(), ","), join(iface, ","));
    self->send(sub_et, get_state_msg {});
    // we expect three 42s
    int i = 0;
    self->receive_for(i, 3)([](int value) { BOOST_CHECK_EQUAL(value, 42); });
    self->receive([&](const std::string &str) { result = str; },
                  after(std::chrono::minutes(1)) >> [&] { BOOST_FAIL("event_testee does not reply"); });
    BOOST_CHECK_EQUAL(result, "wait4int");
}

BOOST_AUTO_TEST_CASE(string_delegator_chain_test) {
    // run test series with string reverter
    auto aut = self->spawn<monitored>(string_delegator, system.spawn(string_reverter), true);
    std::set<std::string> iface {"nil::actor::replies_to<@str>::with<@str>"};
    BOOST_CHECK(aut->message_types() == iface);
    self->request(aut, infinite, "Hello World!")
        .receive([](const std::string &answer) { BOOST_CHECK_EQUAL(answer, "!dlroW olleH"); }, ERROR_HANDLER);
}

BOOST_AUTO_TEST_CASE(maybe_string_delegator_chain_test) {
    ACTOR_LOG_TRACE(ACTOR_ARG(self));
    auto aut = system.spawn(maybe_string_delegator, system.spawn(maybe_string_reverter));
    BOOST_TEST_MESSAGE("send empty string, expect error");
    self->request(aut, infinite, "")
        .receive([](ok_atom, const std::string &) { BOOST_FAIL("unexpected string response"); },
                 [](const error &err) {
                     BOOST_CHECK(err.category() == atom("mock"));
                     BOOST_CHECK_EQUAL(err.code(), static_cast<uint8_t>(mock_errc::cannot_revert_empty));
                 });
    BOOST_TEST_MESSAGE("send abcd string, expect dcba");
    self->request(aut, infinite, "abcd")
        .receive([](ok_atom, const std::string &str) { BOOST_CHECK_EQUAL(str, "dcba"); }, ERROR_HANDLER);
}

BOOST_AUTO_TEST_CASE(sending_typed_actors_test) {
    auto aut = system.spawn(int_fun);
    self->send(self->spawn(foo), 10, aut);
    self->receive([](int i) { BOOST_CHECK_EQUAL(i, 100); });
    self->spawn(foo3);
}

BOOST_AUTO_TEST_CASE(sending_typed_actors_and_down_msg_test) {
    auto aut = system.spawn(int_fun2);
    self->send(self->spawn(foo2), 10, aut);
    self->receive([](int i) { BOOST_CHECK_EQUAL(i, 100); });
}

BOOST_AUTO_TEST_CASE(check_signature_test) {
    using foo_type = typed_actor<replies_to<put_atom>::with<ok_atom>>;
    using foo_result_type = optional<ok_atom>;
    using bar_type = typed_actor<reacts_to<ok_atom>>;
    auto foo_action = [](foo_type::pointer ptr) -> foo_type::behavior_type {
        return {[=](put_atom) -> foo_result_type {
            ptr->quit();
            return {ok_atom::value};
        }};
    };
    auto bar_action = [=](bar_type::pointer ptr) -> bar_type::behavior_type {
        auto foo = ptr->spawn<linked>(foo_action);
        ptr->send(foo, put_atom::value);
        return {[=](ok_atom) { ptr->quit(); }};
    };
    auto x = self->spawn(bar_action);
    self->wait_for(x);
}

BOOST_AUTO_TEST_SUITE_END()

#endif    // ACTOR_WINDOWS
