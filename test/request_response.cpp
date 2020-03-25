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

#define BOOST_TEST_MODULE request_response_test

#include <boost/test/unit_test.hpp>

#include <nil/actor/test/dsl.hpp>

#include <utility>

#include <nil/actor/config.hpp>
#include <nil/actor/all.hpp>

#define ERROR_HANDLER [&](error &err) { BOOST_FAIL(system.render(err)); }

using namespace std;
using namespace nil::actor;

using std::chrono::milliseconds;

namespace {

    using f_atom = atom_constant<atom("f")>;
    using i_atom = atom_constant<atom("i")>;
    using idle_atom = atom_constant<atom("idle")>;
    using error_atom = atom_constant<atom("error")>;
    using request_atom = atom_constant<atom("request")>;
    using response_atom = atom_constant<atom("response")>;
    using go_atom = atom_constant<atom("go")>;
    using gogo_atom = atom_constant<atom("gogo")>;
    using gogogo_atom = atom_constant<atom("gogogo")>;
    using no_way_atom = atom_constant<atom("NoWay")>;
    using hi_there_atom = atom_constant<atom("HiThere")>;

    struct sync_mirror : event_based_actor {
        sync_mirror(actor_config &cfg) : event_based_actor(cfg) {
            // nop
        }

        behavior make_behavior() override {
            set_default_handler(reflect);
            return {[] {
                // nop
            }};
        }
    };

    // replies to 'f' with 0.0f and to 'i' with 0
    struct float_or_int : event_based_actor {
        float_or_int(actor_config &cfg) : event_based_actor(cfg) {
            // nop
        }

        behavior make_behavior() override {
            return {[](f_atom) { return 0.0f; }, [](i_atom) { return 0; }};
        }
    };

    class popular_actor : public event_based_actor {    // popular actors have a buddy
    public:
        explicit popular_actor(actor_config &cfg, actor buddy_arg) :
            event_based_actor(cfg), buddy_(std::move(buddy_arg)) {
            // don't pollute unit test output with (provoked) warnings
            set_default_handler(drop);
        }

        inline const actor &buddy() const {
            return buddy_;
        }

    private:
        actor buddy_;
    };

    /******************************************************************************\
     *                                test case 1:                                *
     *                                                                            *
     *                  A                  B                  C                   *
     *                  |                  |                  |                   *
     *                  | --(delegate)---> |                  |                   *
     *                  |                  | --(forward)----> |                   *
     *                  |                  X                  |---\               *
     *                  |                                     |   |               *
     *                  |                                     |<--/               *
     *                  | <-------------(reply)-------------- |                   *
     *                  X                                     X                   *
    \******************************************************************************/

    class A : public popular_actor {
    public:
        explicit A(actor_config &cfg, const actor &buddy_arg) : popular_actor(cfg, buddy_arg) {
            // nop
        }

        behavior make_behavior() override {
            return {[=](go_atom, const actor &next) { return delegate(next, gogo_atom::value); }};
        }
    };

    class B : public popular_actor {
    public:
        explicit B(actor_config &cfg, const actor &buddy_arg) : popular_actor(cfg, buddy_arg) {
            // nop
        }

        behavior make_behavior() override {
            return {[=](gogo_atom x) {
                BOOST_TEST_MESSAGE("forward message to buddy");
                quit();
                return delegate(buddy(), x);
            }};
        }
    };

    class C : public event_based_actor {
    public:
        C(actor_config &cfg) : event_based_actor(cfg) {
            // don't pollute unit test output with (provoked) warnings
            set_default_handler(drop);
        }

        behavior make_behavior() override {
            return {[=](gogo_atom) -> atom_value {
                BOOST_TEST_MESSAGE("received `gogo_atom`, about to quit");
                quit();
                return ok_atom::value;
            }};
        }
    };

    /******************************************************************************\
     *                                test case 2:                                *
     *                                                                            *
     *                  A                  D                  C                   *
     *                  |                  |                  |                   *
     *                  | ---(request)---> |                  |                   *
     *                  |                  | ---(request)---> |                   *
     *                  |                  |                  |---\               *
     *                  |                  |                  |   |               *
     *                  |                  |                  |<--/               *
     *                  |                  | <---(reply)----- |                   *
     *                  | <---(reply)----- |                                      *
     *                  X                  X                                      *
    \******************************************************************************/

    class D : public popular_actor {
    public:
        explicit D(actor_config &cfg, const actor &buddy_arg) : popular_actor(cfg, buddy_arg) {
            // nop
        }

        behavior make_behavior() override {
            return {[=](gogo_atom gogo) -> response_promise {
                auto rp = make_response_promise();
                request(buddy(), infinite, gogo).then([=](ok_atom ok) mutable {
                    rp.deliver(ok);
                    quit();
                });
                return rp;
            }};
        }
    };

    /******************************************************************************\
     *                                test case 3:                                *
     *                                                                            *
     *                Client            Server              Worker                *
     *                  |                  |                  |                   *
     *                  |                  | <---(idle)------ |                   *
     *                  | ---(request)---> |                  |                   *
     *                  |                  | ---(request)---> |                   *
     *                  |                  |                  |---\               *
     *                  |                  X                  |   |               *
     *                  |                                     |<--/               *
     *                  | <------------(response)------------ |                   *
     *                  X                                                         *
    \******************************************************************************/

    behavior server(event_based_actor *self) {
        return {[=](idle_atom, actor worker) {
                    self->become(
                        keep_behavior,
                        [=](request_atom task) {
                            self->unbecome();    // await next idle message
                            return self->delegate(worker, task);
                        },
                        [](idle_atom) { return skip(); });
                },
                [](request_atom) { return skip(); }};
    }

    struct fixture {
        spawner_config cfg;
        spawner system;
        scoped_actor self;

        fixture() : system(cfg), self(system) {
            // nop
        }
    };

}    // namespace

BOOST_FIXTURE_TEST_SUITE(request_response_tests1, fixture)

BOOST_AUTO_TEST_CASE(test_void_res_test) {
    using testee_a = typed_actor<replies_to<int, int>::with<void>>;
    auto buddy = system.spawn([]() -> testee_a::behavior_type {
        return [](int, int) {
            // nop
        };
    });
    self->request(buddy, infinite, 1, 2).receive([] { BOOST_TEST_MESSAGE("received void res"); }, ERROR_HANDLER);
}

BOOST_AUTO_TEST_CASE(pending_quit_test) {
    auto mirror = system.spawn([](event_based_actor *ptr) -> behavior {
        ptr->set_default_handler(reflect);
        return {[] {
            // nop
        }};
    });
    system.spawn([mirror](event_based_actor *ptr) {
        ptr->request(mirror, infinite, 42)
            .then([](int) { BOOST_ERROR("received result, should've been terminated already"); },
                  [](const error &err) { BOOST_CHECK(err == sec::request_receiver_down); });
        ptr->quit();
    });
}

BOOST_AUTO_TEST_CASE(request_float_or_int_test) {
    int invocations = 0;
    auto foi = self->spawn<float_or_int, linked>();
    self->send(foi, i_atom::value);
    self->receive([](int i) { BOOST_CHECK_EQUAL(i, 0); });
    self->request(foi, infinite, i_atom::value)
        .receive(
            [&](int i) {
                BOOST_CHECK_EQUAL(i, 0);
                ++invocations;
            },
            [&](const error &err) { BOOST_ERROR("Error: " << self->system().render(err)); });
    self->request(foi, infinite, f_atom::value)
        .receive(
            [&](float f) {
                BOOST_CHECK_EQUAL(f, 0.f);
                ++invocations;
            },
            [&](const error &err) { BOOST_ERROR("Error: " << self->system().render(err)); });
    BOOST_CHECK_EQUAL(invocations, 2);
    BOOST_TEST_MESSAGE("trigger sync failure");
    self->request(foi, infinite, f_atom::value)
        .receive([&](int) { BOOST_FAIL("int handler called"); },
                 [&](error &err) {
                     BOOST_TEST_MESSAGE("error received");
                     BOOST_CHECK(err == sec::unexpected_response);
                 });
}

BOOST_AUTO_TEST_CASE(request_to_mirror_test) {
    auto mirror = system.spawn<sync_mirror>();
    self->request(mirror, infinite, 42).receive([&](int value) { BOOST_CHECK_EQUAL(value, 42); }, ERROR_HANDLER);
}

BOOST_AUTO_TEST_CASE(request_to_a_fwd2_b_fwd2_c_test) {
    self->request(self->spawn<A, monitored>(self), infinite, go_atom::value, self->spawn<B>(self->spawn<C>()))
        .receive([](ok_atom) { BOOST_TEST_MESSAGE("received 'ok'"); }, ERROR_HANDLER);
}

BOOST_AUTO_TEST_CASE(request_to_a_fwd2_d_fwd2_c_test) {
    self->request(self->spawn<A, monitored>(self), infinite, go_atom::value, self->spawn<D>(self->spawn<C>()))
        .receive([](ok_atom) { BOOST_TEST_MESSAGE("received 'ok'"); }, ERROR_HANDLER);
}

BOOST_AUTO_TEST_CASE(request_to_self_test) {
    self->request(self, milliseconds(50), no_way_atom::value)
        .receive([&] { BOOST_ERROR("unexpected empty message"); },
                 [&](const error &err) {
                     BOOST_TEST_MESSAGE("err = " << system.render(err));
                     BOOST_REQUIRE(err == sec::request_timeout);
                 });
}

BOOST_AUTO_TEST_CASE(invalid_request_test) {
    self->request(self->spawn<C>(), milliseconds(500), hi_there_atom::value)
        .receive([&](hi_there_atom) { BOOST_ERROR("C did reply to 'HiThere'"); },
                 [&](const error &err) { BOOST_REQUIRE(err == sec::unexpected_message); });
}

BOOST_AUTO_TEST_CASE(client_server_worker_user_case_test) {
    auto serv = self->spawn<linked>(server);              // server
    auto work = self->spawn<linked>([]() -> behavior {    // worker
        return {[](request_atom) { return response_atom::value; }};
    });
    // first 'idle', then 'request'
    anon_send(serv, idle_atom::value, work);
    self->request(serv, infinite, request_atom::value)
        .receive(
            [&](response_atom) {
                BOOST_TEST_MESSAGE("received 'response'");
                BOOST_CHECK(self->current_sender() == work);
            },
            [&](const error &err) { BOOST_ERROR("error: " << self->system().render(err)); });
    // first 'request', then 'idle'
    auto handle = self->request(serv, infinite, request_atom::value);
    send_as(work, serv, idle_atom::value, work);
    handle.receive([&](response_atom) { BOOST_CHECK(self->current_sender() == work.address()); },
                   [&](const error &err) { BOOST_ERROR("error: " << self->system().render(err)); });
}

behavior request_no_then_A(event_based_actor *) {
    return [=](int number) { BOOST_TEST_MESSAGE("got " << number); };
}

behavior request_no_then_B(event_based_actor *self) {
    return {[=](int number) { self->request(self->spawn(request_no_then_A), infinite, number); }};
}

BOOST_AUTO_TEST_CASE(request_no_then_test) {
    anon_send(system.spawn(request_no_then_B), 8);
}

BOOST_AUTO_TEST_CASE(async_request_test) {
    auto foo = system.spawn([](event_based_actor *ptr) -> behavior {
        auto receiver = ptr->spawn<linked>(
            [](event_based_actor *ptr2) -> behavior { return {[=](int) { return ptr2->make_response_promise(); }}; });
        ptr->request(receiver, infinite, 1).then([=](int) {});
        return {[=](int) {
            BOOST_TEST_MESSAGE("int received");
            ptr->quit(exit_reason::user_shutdown);
        }};
    });
    anon_send(foo, 1);
}

BOOST_AUTO_TEST_CASE(skip_responses_test) {
    auto mirror = system.spawn<sync_mirror>();
    auto future = self->request(mirror, infinite, 42);
    self->send(mirror, 42);
    self->receive([](int x) { BOOST_CHECK_EQUAL(x, 42); });
    // second receive must time out
    self->receive([](int) { BOOST_FAIL("received response message as ordinary message"); },
                  after(std::chrono::milliseconds(20)) >>
                      [] { BOOST_TEST_MESSAGE("second receive timed out as expected"); });
    future.receive([](int x) { BOOST_CHECK_EQUAL(x, 42); }, [&](const error &err) { BOOST_FAIL(system.render(err)); });
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(request_response_tests2, test_coordinator_fixture<>)

BOOST_AUTO_TEST_CASE(request_response_in_test_coordinator_test) {
    auto mirror = sys.spawn<sync_mirror>();
    sched.run();
    sched.inline_next_enqueue();
    // this block would deadlock without inlining the next enqueue
    self->request(mirror, infinite, 23)
        .receive([](int x) { BOOST_CHECK_EQUAL(x, 23); },
                 [&](const error &err) { BOOST_FAIL("unexpected error: " << sys.render(err)); });
}

BOOST_AUTO_TEST_SUITE_END()
