//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE selective_streaming

#include "core_test.hpp"

#include <memory>
#include <numeric>

#include <nil/actor/spawner.hpp>
#include <nil/actor/spawner_config.hpp>
#include <nil/actor/attach_continuous_stream_stage.hpp>
#include <nil/actor/attach_stream_sink.hpp>
#include <nil/actor/attach_stream_source.hpp>
#include <nil/actor/broadcast_downstream_manager.hpp>
#include <nil/actor/event_based_actor.hpp>
#include <nil/actor/stateful_actor.hpp>

using namespace nil::actor;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<template<typename...> class P, typename... T>
            struct print_log_value<P<T...>> {
                void operator()(std::ostream &, P<T...> const &) {
                }
            };

            template<template<typename, std::size_t> class P, typename T, std::size_t S>
            struct print_log_value<P<T, S>> {
                void operator()(std::ostream &, P<T, S> const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

namespace {

    using value_type = std::pair<level, std::string>;

    struct select {
        static bool apply(level x, const value_type &y) noexcept {
            return x == level::all || x == y.first;
        }
        bool operator()(level x, const value_type &y) const noexcept {
            return apply(x, y);
        }
    };

    using manager_type = broadcast_downstream_manager<value_type, level, select>;

    using buf = std::vector<value_type>;

    buf make_log(level lvl) {
        buf result {{level::trace, "trace1"},
                    {level::trace, "trace2"},
                    {level::debug, "debug1"},
                    {level::error, "errro1"},
                    {level::trace, "trace3"}};
        auto predicate = [=](const value_type &x) { return !select::apply(lvl, x); };
        auto e = result.end();
        auto i = std::remove_if(result.begin(), e, predicate);
        if (i != e)
            result.erase(i, e);
        return result;
    }

    TESTEE_SETUP();

    TESTEE(log_producer) {
        return {
            [=](level lvl) -> result<stream<value_type>> {
                auto res = attach_stream_source(
                    self,
                    // initialize state
                    [=](buf &xs) { xs = make_log(lvl); },
                    // get next element
                    [](buf &xs, downstream<value_type> &out, size_t num) {
                        BOOST_TEST_MESSAGE("push " << num << " messages downstream");
                        auto n = std::min(num, xs.size());
                        for (size_t i = 0; i < n; ++i)
                            out.push(xs[i]);
                        xs.erase(xs.begin(), xs.begin() + static_cast<ptrdiff_t>(n));
                    },
                    // check whether we reached the end
                    [=](const buf &xs) {
                        if (xs.empty()) {
                            BOOST_TEST_MESSAGE(self->name() << " is done");
                            return true;
                        }
                        return false;
                    },
                    unit, policy::arg<manager_type>::value);
                auto &out = res.ptr()->out();
                static_assert(std::is_same<decltype(out), manager_type &>::value, "source has wrong manager_type type");
                out.set_filter(res.outbound_slot(), lvl);
                return res;
            },
        };
    }

    TESTEE_STATE(log_dispatcher) {
        stream_stage_ptr<value_type, manager_type> stage;
    };

    TESTEE(log_dispatcher) {
        self->state.stage = attach_continuous_stream_stage(
            self,
            // initialize state
            [](unit_t &) {
                // nop
            },
            // processing step
            [](unit_t &, downstream<value_type> &out, value_type x) { out.push(std::move(x)); },
            // cleanup
            [=](unit_t &, const error &) { BOOST_TEST_MESSAGE(self->name() << " is done"); },
            policy::arg<manager_type>::value);
        return {
            [=](join_atom, level lvl) {
                auto &stg = self->state.stage;
                BOOST_TEST_MESSAGE("received 'join' request");
                auto result = stg->add_outbound_path();
                stg->out().set_filter(result, lvl);
                return result;
            },
            [=](const stream<value_type> &in) { self->state.stage->add_inbound_path(in); },
        };
    }

    TESTEE_STATE(log_consumer) {
        std::vector<value_type> log;
    };

    TESTEE(log_consumer) {
        return {
            [=](stream<value_type> &in) {
                return attach_stream_sink(
                    self,
                    // input stream
                    in,
                    // initialize state
                    [=](unit_t &) {
                        // nop
                    },
                    // processing step
                    [=](unit_t &, value_type x) { self->state.log.emplace_back(std::move(x)); },
                    // cleanup and produce result message
                    [=](unit_t &, const error &) { BOOST_TEST_MESSAGE(self->name() << " is done"); });
            },
        };
    }

}    // namespace

// -- unit tests ---------------------------------------------------------------

BOOST_FIXTURE_TEST_SUITE(selective_streaming_tests, test_coordinator_fixture<>)

BOOST_AUTO_TEST_CASE(select_all) {
    auto src = sys.spawn(log_producer);
    auto snk = sys.spawn(log_consumer);
    BOOST_TEST_MESSAGE(ACTOR_ARG(self) << ACTOR_ARG(src) << ACTOR_ARG(snk));
    BOOST_TEST_MESSAGE("initiate stream handshake");
    self->send(snk * src, level::all);
    run();
    BOOST_CHECK_EQUAL(deref<log_consumer_actor>(snk).state.log, make_log(level::all));
}

BOOST_AUTO_TEST_CASE(select_trace) {
    auto src = sys.spawn(log_producer);
    auto snk = sys.spawn(log_consumer);
    BOOST_TEST_MESSAGE(ACTOR_ARG(self) << ACTOR_ARG(src) << ACTOR_ARG(snk));
    BOOST_TEST_MESSAGE("initiate stream handshake");
    self->send(snk * src, level::trace);
    run();
    BOOST_CHECK_EQUAL(deref<log_consumer_actor>(snk).state.log, make_log(level::trace));
}

BOOST_AUTO_TEST_CASE(forking) {
    auto src = sys.spawn(log_producer);
    auto stg = sys.spawn(log_dispatcher);
    auto snk1 = sys.spawn(log_consumer);
    auto snk2 = sys.spawn(log_consumer);
    sched.run();
    self->send(stg * src, level::all);
    self->send(snk1 * stg, join_atom_v, level::trace);
    self->send(snk2 * stg, join_atom_v, level::error);
    sched.run();
    auto &st = deref<log_dispatcher_actor>(stg).state;
    run_until([&] { return st.stage->inbound_paths().empty() && st.stage->out().clean(); });
    BOOST_CHECK_EQUAL(deref<log_consumer_actor>(snk1).state.log, make_log(level::trace));
    BOOST_CHECK_EQUAL(deref<log_consumer_actor>(snk2).state.log, make_log(level::error));
    self->send(stg, exit_reason::kill);
}

BOOST_AUTO_TEST_SUITE_END()
