//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE tracing_data

#include <nil/actor/tracing_data.hpp>

#include "core-test.hpp"

#include <vector>

#include <nil/actor/actor_profiler.hpp>
#include <nil/actor/binary_deserializer.hpp>
#include <nil/actor/binary_serializer.hpp>
#include <nil/actor/config.hpp>
#include <nil/actor/tracing_data_factory.hpp>

#ifdef ACTOR_ENABLE_ACTOR_PROFILER

using std::string;

using namespace nil::actor;

namespace {

    class dummy_tracing_data : public tracing_data {
    public:
        string value;

        dummy_tracing_data(string value) : value(std::move(value)) {
            // nop
        }

        error serialize(serializer &sink) const override {
            return sink(value);
        }

        error_code<sec> serialize(binary_serializer &sink) const override {
            return sink(value);
        }
    };

    class dummy_tracing_data_factory : public tracing_data_factory {
    public:
        error deserialize(deserializer &source, std::unique_ptr<tracing_data> &dst) const override {
            return deserialize_impl(source, dst);
        }

        error_code<sec> deserialize(binary_deserializer &source, std::unique_ptr<tracing_data> &dst) const override {
            return deserialize_impl(source, dst);
        }

    private:
        template<class Deserializer>
        typename Deserializer::result_type deserialize_impl(Deserializer &source,
                                                            std::unique_ptr<tracing_data> &dst) const {
            string value;
            if (auto err = source(value))
                return err;
            dst.reset(new dummy_tracing_data(std::move(value)));
            return {};
        }
    };

    class dummy_profiler : public actor_profiler {
    public:
        void add_actor(const local_actor &, const local_actor *) override {
            // nop
        }

        void remove_actor(const local_actor &) override {
            // nop
        }

        void before_processing(const local_actor &, const mailbox_element &) override {
            // nop
        }

        void after_processing(const local_actor &, invoke_message_result) override {
            // nop
        }

        void before_sending(const local_actor &self, mailbox_element &element) override {
            element.tracing_id.reset(new dummy_tracing_data(self.name()));
        }

        void before_sending_scheduled(const local_actor &self, actor_clock::time_point,
                                      mailbox_element &element) override {
            element.tracing_id.reset(new dummy_tracing_data(self.name()));
        }
    };

    spawner_config &init(spawner_config &cfg, actor_profiler &profiler, tracing_data_factory &factory) {
        test_coordinator_fixture<>::init_config(cfg);
        cfg.profiler = &profiler;
        cfg.tracing_context = &factory;
        return cfg;
    }

    struct fixture {
        using scheduler_type = nil::actor::scheduler::test_coordinator;

        fixture() : sys(init(cfg, profiler, factory)), sched(dynamic_cast<scheduler_type &>(sys.scheduler())) {
            run();
        }

        void run() {
            sched.run();
        }

        dummy_profiler profiler;
        dummy_tracing_data_factory factory;
        spawner_config cfg;
        spawner sys;
        scheduler_type &sched;
    };

    const std::string &tracing_id(local_actor *self) {
        auto element = self->current_mailbox_element();
        if (element == nullptr)
            BOOST_FAIL("current_mailbox_element == null");
        auto tid = element->tracing_id.get();
        if (tid == nullptr)
            BOOST_FAIL("tracing_id == null");
        auto dummy_tid = dynamic_cast<dummy_tracing_data *>(tid);
        if (dummy_tid == nullptr)
            BOOST_FAIL("dummy_tracing_id == null");
        return dummy_tid->value;
    }

#define NAMED_ACTOR_STATE(type)   \
    struct type##_state {         \
        const char *name = #type; \
    }

    NAMED_ACTOR_STATE(alice);
    NAMED_ACTOR_STATE(bob);
    NAMED_ACTOR_STATE(carl);

}    // namespace

BOOST_FIXTURE_TEST_SUITE(actor_profiler_tests, fixture)

BOOST_AUTO_TEST_CASE(profilers_inject_tracing_data_into_asynchronous_messages) {
    BOOST_TEST_MESSAGE("spawn a foo and a bar");
    auto carl_fun = [](stateful_actor<carl_state> *self) -> behavior {
        return {
            [=](const string &str) {
                BOOST_CHECK_EQUAL(str, "hello carl");
                BOOST_CHECK_EQUAL(tracing_id(self), "bob");
            },
        };
    };
    auto bob_fun = [](stateful_actor<bob_state> *self, actor carl) -> behavior {
        return {
            [=](const string &str) {
                BOOST_CHECK_EQUAL(str, "hello bob");
                BOOST_CHECK_EQUAL(tracing_id(self), "alice");
                self->send(carl, "hello carl");
            },
        };
    };
    auto alice_fun = [](stateful_actor<alice_state> *self, actor bob) { self->send(bob, "hello bob"); };
    sys.spawn(alice_fun, sys.spawn(bob_fun, sys.spawn(carl_fun)));
    run();
}

BOOST_AUTO_TEST_CASE(tracing_data_is_serializable) {
    byte_buffer buf;
    binary_serializer sink {sys, buf};
    tracing_data_ptr data;
    tracing_data_ptr copy;
    data.reset(new dummy_tracing_data("iTrace"));
    BOOST_CHECK_EQUAL(sink(data), none);
    binary_deserializer source {sys, buf};
    BOOST_CHECK_EQUAL(source(copy), none);
    BOOST_REQUIRE_NOT_EQUAL(copy.get(), nullptr);
    BOOST_CHECK_EQUAL(dynamic_cast<dummy_tracing_data &>(*copy).value, "iTrace");
}

BOOST_AUTO_TEST_SUITE_END()

#endif    // ACTOR_ENABLE_ACTOR_PROFILER
