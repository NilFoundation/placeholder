//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE actor_profiler

#include <nil/actor/actor_profiler.hpp>

#include <nil/actor/test/dsl.hpp>

#include <nil/actor/config.hpp>

#ifdef ACTOR_ENABLE_ACTOR_PROFILER

using namespace nil::actor;

namespace {

    using string_list = std::vector<std::string>;

    struct recorder : actor_profiler {
        void add_actor(const local_actor &self, const local_actor *parent) override {
            log.emplace_back("new: ");
            auto &str = log.back();
            str += self.name();
            if (parent != nullptr) {
                str += ", parent: ";
                str += parent->name();
            }
        }

        void remove_actor(const local_actor &self) override {
            log.emplace_back("delete: ");
            log.back() += self.name();
        }

        void before_processing(const local_actor &self, const mailbox_element &element) override {
            log.emplace_back(self.name());
            auto &str = log.back();
            str += " got: ";
            str += to_string(element.content());
        }

        void after_processing(const local_actor &self, invoke_message_result result) override {
            log.emplace_back(self.name());
            auto &str = log.back();
            str += " ";
            str += to_string(result);
            str += " the message";
        }

        void before_sending(const local_actor &self, mailbox_element &element) override {
            log.emplace_back(self.name());
            auto &str = log.back();
            str += " sends: ";
            str += to_string(element.content());
        }

        void before_sending_scheduled(const local_actor &self,
                                      actor_clock::time_point,
                                      mailbox_element &element) override {
            log.emplace_back(self.name());
            auto &str = log.back();
            str += " sends (scheduled): ";
            str += to_string(element.content());
        }

        string_list log;
    };

    spawner_config &init(spawner_config &cfg, recorder &rec) {
        test_coordinator_fixture<>::init_config(cfg);
        cfg.profiler = &rec;
        return cfg;
    }

    struct fixture {
        using scheduler_type = nil::actor::scheduler::test_coordinator;

        fixture() : sys(init(cfg, rec)), sched(dynamic_cast<scheduler_type &>(sys.scheduler())) {
            // nop
        }

        void run() {
            sched.run();
        }

        recorder rec;
        spawner_config cfg;
        spawner sys;
        scheduler_type &sched;
    };

#define NAMED_ACTOR_STATE(type)   \
    struct type##_state {         \
        const char *name = #type; \
    }

    NAMED_ACTOR_STATE(bar);
    NAMED_ACTOR_STATE(client);
    NAMED_ACTOR_STATE(foo);
    NAMED_ACTOR_STATE(server);
    NAMED_ACTOR_STATE(worker);

}    // namespace

BOOST_FIXTURE_TEST_SUITE(actor_profiler_tests, fixture)

BOOST_AUTO_TEST_CASE(profilers_record_actor_construction) {
    BOOST_TEST_MESSAGE("fully initialize =nil; Actor, ignore system-internal actors");
    run();
    rec.log.clear();
    BOOST_TEST_MESSAGE("spawn a foo and a bar");
    auto bar = [](stateful_actor<bar_state> *) {};
    auto foo = [bar](stateful_actor<foo_state> *self) { self->spawn(bar); };
    auto foo_actor = sys.spawn(foo);
    run();
    foo_actor = nullptr;
    BOOST_CHECK_EQUAL(string_list({
                        "new: foo",
                        "new: bar, parent: foo",
                        "delete: bar",
                        "delete: foo",
                    }),
                    rec.log);
}

BOOST_AUTO_TEST_CASE(profilers_record_asynchronous_messaging) {
    BOOST_TEST_MESSAGE("fully initialize =nil; Actor, ignore system-internal actors");
    run();
    rec.log.clear();
    BOOST_TEST_MESSAGE("spawn a foo and a bar");
    auto bar = [](stateful_actor<bar_state> *) -> behavior {
        return {
            [](const std::string &str) {
                BOOST_CHECK_EQUAL(str, "hello bar");
                return "hello foo";
            },
        };
    };
    auto foo = [bar](stateful_actor<foo_state> *self) -> behavior {
        auto b = self->spawn(bar);
        self->send(b, "hello bar");
        return {
            [](const std::string &str) { BOOST_CHECK_EQUAL(str, "hello foo"); },
        };
    };
    sys.spawn(foo);
    run();
    BOOST_CHECK_EQUAL(string_list({
                        "new: foo",
                        "new: bar, parent: foo",
                        "foo sends: (\"hello bar\")",
                        "bar got: (\"hello bar\")",
                        "bar sends: (\"hello foo\")",
                        "bar consumed the message",
                        "foo got: (\"hello foo\")",
                        "delete: bar",
                        "foo consumed the message",
                        "delete: foo",
                    }),
                    rec.log);
}

BOOST_AUTO_TEST_CASE(profilers record request / response messaging) {
    BOOST_TEST_MESSAGE("fully initialize =nil; Actor, ignore system-internal actors");
    run();
    rec.log.clear();
    BOOST_TEST_MESSAGE("spawn a client and a server with one worker");
    auto worker = [](stateful_actor<worker_state> *) -> behavior {
        return {
            [](int x, int y) { return x + y; },
        };
    };
    auto server = [](stateful_actor<server_state> *self, actor work) -> behavior {
        return {
            [=](int x, int y) { return self->delegate(work, x, y); },
        };
    };
    auto client = [](stateful_actor<client_state> *self, actor serv) {
        self->request(serv, infinite, 19, 23).then([](int result) { BOOST_CHECK_EQUAL(result, 42); });
    };
    sys.spawn(client, sys.spawn(server, sys.spawn(worker)));
    run();
    for (const auto &line : rec.log) {
        BOOST_TEST_MESSAGE(line);
    }
    BOOST_CHECK_EQUAL(string_list({
                        "new: worker",
                        "new: server",
                        "new: client",
                        "client sends: (19, 23)",
                        "server got: (19, 23)",
                        "server sends: (19, 23)",
                        "server consumed the message",
                        "delete: server",
                        "worker got: (19, 23)",
                        "worker sends: (42)",
                        "worker consumed the message",
                        "client got: (42)",
                        "client consumed the message",
                        "delete: worker",
                        "delete: client",
                    }),
                    rec.log);
}

BOOST_AUTO_TEST_SUITE_END()

#endif    // ACTOR_ENABLE_ACTOR_PROFILER
