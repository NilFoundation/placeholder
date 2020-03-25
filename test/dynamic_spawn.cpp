//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt or
// http://opensource.org/licenses/BSD-3-Clause
//---------------------------------------------------------------------------//

#include <nil/actor/config.hpp>

#define BOOST_TEST_MODULE dynamic_spawn_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/chrono/duration.hpp>

#include <stack>
#include <atomic>
#include <iostream>
#include <functional>

#include <nil/actor/all.hpp>

using namespace nil::actor;

namespace {

    std::atomic<long> s_max_actor_instances;
    std::atomic<long> s_actor_instances;

    using a_atom = atom_constant<atom("a")>;
    using b_atom = atom_constant<atom("b")>;
    using c_atom = atom_constant<atom("c")>;
    using abc_atom = atom_constant<atom("abc")>;
    using name_atom = atom_constant<atom("name")>;

    void inc_actor_instances() {
        long v1 = ++s_actor_instances;
        long v2 = s_max_actor_instances.load();
        while (v1 > v2) {
            s_max_actor_instances.compare_exchange_strong(v2, v1);
        }
    }

    void dec_actor_instances() {
        --s_actor_instances;
    }

    class event_testee : public event_based_actor {
    public:
        event_testee(actor_config &cfg) : event_based_actor(cfg) {
            inc_actor_instances();
            wait4string.assign([=](const std::string &) { become(wait4int); }, [=](get_atom) { return "wait4string"; });
            wait4float.assign([=](float) { become(wait4string); }, [=](get_atom) { return "wait4float"; });
            wait4int.assign([=](int) { become(wait4float); }, [=](get_atom) { return "wait4int"; });
        }

        ~event_testee() override {
            dec_actor_instances();
        }

        behavior make_behavior() override {
            return wait4int;
        }

        behavior wait4string;
        behavior wait4float;
        behavior wait4int;
    };

    // quits after 5 timeouts
    actor spawn_event_testee2(scoped_actor &parent) {
        struct impl : event_based_actor {
            actor parent;

            impl(actor_config &cfg, actor parent_actor) : event_based_actor(cfg), parent(std::move(parent_actor)) {
                inc_actor_instances();
            }

            ~impl() override {
                dec_actor_instances();
            }

            behavior wait4timeout(int remaining) {
                return {after(std::chrono::milliseconds(1)) >> [=] {
                    BOOST_TEST_MESSAGE("remaining: " << remaining);
                    if (remaining == 1) {
                        send(parent, ok_atom::value);
                        quit();
                    } else {
                        become(wait4timeout(remaining - 1));
                    }
                }};
            }

            behavior make_behavior() override {
                return wait4timeout(5);
            }
        };
        return parent->spawn<impl>(parent);
    }

    class testee_actor : public blocking_actor {
    public:
        testee_actor(actor_config &cfg) : blocking_actor(cfg) {
            inc_actor_instances();
        }

        ~testee_actor() override {
            dec_actor_instances();
        }

        void act() override {
            bool running = true;
            receive_while(running)([&](int) { wait4float(); }, [&](get_atom) { return "wait4int"; },
                                   [&](exit_msg &em) {
                                       if (em.reason) {
                                           fail_state(std::move(em.reason));
                                           running = false;
                                       }
                                   });
        }

    private:
        void wait4string() {
            bool string_received = false;
            do_receive([&](const std::string &) { string_received = true; }, [&](get_atom) { return "wait4string"; })
                .until([&] { return string_received; });
        }

        void wait4float() {
            bool float_received = false;
            do_receive([&](float) { float_received = true; }, [&](get_atom) { return "wait4float"; }).until([&] {
                return float_received;
            });
            wait4string();
        }
    };

    // self->receives one timeout and quits
    class testee1 : public event_based_actor {
    public:
        testee1(actor_config &cfg) : event_based_actor(cfg) {
            inc_actor_instances();
        }

        ~testee1() override {
            dec_actor_instances();
        }

        behavior make_behavior() override {
            return {after(std::chrono::milliseconds(10)) >> [=] { unbecome(); }};
        }
    };

    class echo_actor : public event_based_actor {
    public:
        echo_actor(actor_config &cfg) : event_based_actor(cfg) {
            inc_actor_instances();
        }

        ~echo_actor() override {
            dec_actor_instances();
        }

        behavior make_behavior() override {
            set_default_handler(reflect);
            return {[] {
                // nop
            }};
        }
    };

    class simple_mirror : public event_based_actor {
    public:
        simple_mirror(actor_config &cfg) : event_based_actor(cfg) {
            inc_actor_instances();
        }

        ~simple_mirror() override {
            dec_actor_instances();
        }

        behavior make_behavior() override {
            set_default_handler(reflect);
            return {[] {
                // nop
            }};
        }
    };

    behavior master(event_based_actor *self) {
        return ([=](ok_atom) {
            BOOST_TEST_MESSAGE("master: received done");
            self->quit(exit_reason::user_shutdown);
        });
    }

    behavior slave(event_based_actor *self, const actor &master) {
        self->link_to(master);
        self->set_exit_handler([=](exit_msg &msg) {
            BOOST_TEST_MESSAGE("slave: received exit message");
            self->quit(msg.reason);
        });
        return {[] {
            // nop
        }};
    }

    class counting_actor : public event_based_actor {
    public:
        counting_actor(actor_config &cfg) : event_based_actor(cfg) {
            inc_actor_instances();
        }

        ~counting_actor() override {
            dec_actor_instances();
        }

        behavior make_behavior() override {
            for (int i = 0; i < 100; ++i) {
                send(this, ok_atom::value);
            }
            BOOST_CHECK_EQUAL(mailbox().size(), 100u);
            for (int i = 0; i < 100; ++i) {
                send(this, ok_atom::value);
            }
            BOOST_CHECK_EQUAL(mailbox().size(), 200u);
            return {};
        }
    };

    struct fixture {
        spawner_config cfg;
        // put inside a union to control ctor/dtor timing
        union {
            spawner system;
        };

        fixture() {
            new (&system) spawner(cfg);
        }

        ~fixture() {
            system.~spawner();
            // destructor of spawner must make sure all
            // destructors of all actors have been run
            BOOST_CHECK_EQUAL(s_actor_instances.load(), 0);
            BOOST_TEST_MESSAGE("max. # of actor instances: " << s_max_actor_instances.load());
        }
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(atom_tests, fixture)

BOOST_AUTO_TEST_CASE(count_mailbox_test) {
    system.spawn<counting_actor>();
}

BOOST_AUTO_TEST_CASE(detached_actors_and_schedulued_actors_test) {
    scoped_actor self {system};
    // check whether detached actors and scheduled actors interact w/o errors
    auto m = system.spawn<detached>(master);
    system.spawn(slave, m);
    system.spawn(slave, m);
    self->send(m, ok_atom::value);
}

BOOST_AUTO_TEST_CASE(self_receive_with_zero_timeout_test) {
    scoped_actor self {system};
    self->receive([&] { BOOST_ERROR("Unexpected message"); }, after(std::chrono::seconds(0)) >>
                                                                  [] {
                                                                      // mailbox empty
                                                                  });
}

BOOST_AUTO_TEST_CASE(mirror_test) {
    scoped_actor self {system};
    auto mirror = self->spawn<simple_mirror>();
    self->send(mirror, "hello mirror");
    self->receive([](const std::string &msg) { BOOST_CHECK_EQUAL(msg, "hello mirror"); });
}

BOOST_AUTO_TEST_CASE(detached_mirror_test) {
    scoped_actor self {system};
    auto mirror = self->spawn<simple_mirror, detached>();
    self->send(mirror, "hello mirror");
    self->receive([](const std::string &msg) { BOOST_CHECK_EQUAL(msg, "hello mirror"); });
}

BOOST_AUTO_TEST_CASE(send_to_self_test) {
    scoped_actor self {system};
    self->send(self, 1, 2, 3, true);
    self->receive([](int a, int b, int c, bool d) {
        BOOST_CHECK_EQUAL(a, 1);
        BOOST_CHECK_EQUAL(b, 2);
        BOOST_CHECK_EQUAL(c, 3);
        BOOST_CHECK_EQUAL(d, true);
    });
    self->send(self, message {});
    self->receive([] {});
}

BOOST_AUTO_TEST_CASE(echo_actor_messaging_test) {
    scoped_actor self {system};
    auto mecho = system.spawn<echo_actor>();
    self->send(mecho, "hello echo");
    self->receive([](const std::string &arg) { BOOST_CHECK_EQUAL(arg, "hello echo"); });
}

BOOST_AUTO_TEST_CASE(delayed_send_test) {
    scoped_actor self {system};
    self->delayed_send(self, std::chrono::milliseconds(1), 1, 2, 3);
    self->receive([](int a, int b, int c) {
        BOOST_CHECK_EQUAL(a, 1);
        BOOST_CHECK_EQUAL(b, 2);
        BOOST_CHECK_EQUAL(c, 3);
    });
}

BOOST_AUTO_TEST_CASE(delayed_spawn_test) {
    scoped_actor self {system};
    self->receive(after(std::chrono::milliseconds(1)) >> [] {});
    system.spawn<testee1>();
}

BOOST_AUTO_TEST_CASE(spawn_event_testee2_test) {
    scoped_actor self {system};
    spawn_event_testee2(self);
    self->receive([](ok_atom) { BOOST_TEST_MESSAGE("Received 'ok'"); });
}

BOOST_AUTO_TEST_CASE(function_spawn_test) {
    scoped_actor self {system};
    auto f = [](const std::string &name) -> behavior {
        return ([name](get_atom) { return std::make_tuple(name_atom::value, name); });
    };
    auto a1 = system.spawn(f, "alice");
    auto a2 = system.spawn(f, "bob");
    self->send(a1, get_atom::value);
    self->receive([&](name_atom, const std::string &name) { BOOST_CHECK_EQUAL(name, "alice"); });
    self->send(a2, get_atom::value);
    self->receive([&](name_atom, const std::string &name) { BOOST_CHECK_EQUAL(name, "bob"); });
    self->send_exit(a1, exit_reason::user_shutdown);
    self->send_exit(a2, exit_reason::user_shutdown);
}

using typed_testee = typed_actor<replies_to<abc_atom>::with<std::string>>;

typed_testee::behavior_type testee() {
    return {[](abc_atom) {
        BOOST_TEST_MESSAGE("received 'abc'");
        return "abc";
    }};
}

BOOST_AUTO_TEST_CASE(typed_await_test) {
    scoped_actor self {system};
    auto f = make_function_view(system.spawn(testee));
    BOOST_CHECK_EQUAL(f(abc_atom::value), "abc");
}

// tests attach_functor() inside of an actor's constructor
BOOST_AUTO_TEST_CASE(constructor_attach_test) {
    class testee : public event_based_actor {
    public:
        testee(actor_config &cfg, actor buddy) : event_based_actor(cfg), buddy_(buddy) {
            attach_functor([=](const error &reason) { send(buddy, ok_atom::value, reason); });
        }

        behavior make_behavior() override {
            return {[] {
                // nop
            }};
        }

        void on_exit() override {
            destroy(buddy_);
        }

    private:
        actor buddy_;
    };
    class spawner : public event_based_actor {
    public:
        spawner(actor_config &cfg) : event_based_actor(cfg), downs_(0), testee_(spawn<testee, monitored>(this)) {
            set_down_handler([=](down_msg &msg) {
                BOOST_CHECK(msg.reason == exit_reason::user_shutdown);
                if (++downs_ == 2) {
                    quit(msg.reason);
                }
            });
            set_exit_handler([=](exit_msg &msg) { send_exit(testee_, std::move(msg.reason)); });
        }

        behavior make_behavior() override {
            return {[=](ok_atom, const error &reason) {
                BOOST_CHECK(reason == exit_reason::user_shutdown);
                if (++downs_ == 2) {
                    quit(reason);
                }
            }};
        }

        void on_exit() override {
            BOOST_TEST_MESSAGE("spawner::on_exit()");
            destroy(testee_);
        }

    private:
        int downs_;
        actor testee_;
    };
    anon_send_exit(system.spawn<spawner>(), exit_reason::user_shutdown);
}

BOOST_AUTO_TEST_CASE(kill_the_immortal_test) {
    auto wannabe_immortal = system.spawn([](event_based_actor *self) -> behavior {
        self->set_exit_handler([](local_actor *, exit_msg &) {
            // nop
        });
        return {[] {
            // nop
        }};
    });
    scoped_actor self {system};
    self->send_exit(wannabe_immortal, exit_reason::kill);
    self->wait_for(wannabe_immortal);
}

BOOST_AUTO_TEST_CASE(move_only_argument_test) {
    using unique_int = std::unique_ptr<int>;
    unique_int uptr {new int(42)};
    auto impl = [](event_based_actor *self, unique_int ptr) -> behavior {
        auto i = *ptr;
        return {[=](float) {
            self->quit();
            return i;
        }};
    };
    auto f = make_function_view(system.spawn(impl, std::move(uptr)));
    BOOST_CHECK_EQUAL(to_string(f(1.f)), "(42)");
}

BOOST_AUTO_TEST_SUITE_END()
