//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE continuous_streaming

#include <nil/actor/attach_continuous_stream_stage.hpp>

#include "core_test.hpp"

#include <memory>
#include <numeric>

#include <nil/actor/spawner.hpp>
#include <nil/actor/spawner_config.hpp>
#include <nil/actor/attach_stream_sink.hpp>
#include <nil/actor/event_based_actor.hpp>
#include <nil/actor/stateful_actor.hpp>

using std::string;

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

    /// Returns the sum of natural numbers up until `n`, i.e., 1 + 2 + ... + n.
    int32_t sum(int32_t n) {
        return (n * (n + 1)) / 2;
    }

    TESTEE_SETUP();

    TESTEE_STATE(file_reader) {
        std::vector<int32_t> buf;
    };

    VARARGS_TESTEE(file_reader, size_t buf_size) {
        return {[=](string &fname) -> result<stream<int32_t>, string> {
            BOOST_CHECK_EQUAL(fname, "numbers.txt");
            BOOST_CHECK_EQUAL(self->mailbox().empty(), true);
            return attach_stream_source(
                self,
                // forward file name in handshake to next stage
                std::forward_as_tuple(std::move(fname)),
                // initialize state
                [=](unit_t &) {
                    auto &xs = self->state.buf;
                    xs.resize(buf_size);
                    std::iota(xs.begin(), xs.end(), 1);
                },
                // get next element
                [=](unit_t &, downstream<int32_t> &out, size_t num) {
                    auto &xs = self->state.buf;
                    BOOST_TEST_MESSAGE("push " << num << " messages downstream");
                    auto n = std::min(num, xs.size());
                    for (size_t i = 0; i < n; ++i)
                        out.push(xs[i]);
                    xs.erase(xs.begin(), xs.begin() + static_cast<ptrdiff_t>(n));
                },
                // check whether we reached the end
                [=](const unit_t &) {
                    if (self->state.buf.empty()) {
                        BOOST_TEST_MESSAGE(self->name() << " is done");
                        return true;
                    }
                    return false;
                });
        }};
    }

    TESTEE_STATE(sum_up) {
        int32_t x = 0;
    };

    TESTEE(sum_up) {
        return {[=](stream<int32_t> &in, const string &fname) {
                    BOOST_CHECK_EQUAL(fname, "numbers.txt");
                    using int_ptr = int32_t *;
                    return attach_stream_sink(
                        self,
                        // input stream
                        in,
                        // initialize state
                        [=](int_ptr &x) { x = &self->state.x; },
                        // processing step
                        [](int_ptr &x, int32_t y) { *x += y; },
                        // cleanup
                        [=](int_ptr &, const error &) { BOOST_TEST_MESSAGE(self->name() << " is done"); });
                },
                [=](join_atom atm, actor src) {
                    BOOST_TEST_MESSAGE(self->name() << " joins a stream");
                    self->send(self * src, atm);
                }};
    }

    TESTEE_STATE(stream_multiplexer) {
        stream_stage_ptr<int32_t, broadcast_downstream_manager<int32_t>> stage;
    };

    TESTEE(stream_multiplexer) {
        self->state.stage = attach_continuous_stream_stage(
            self,
            // initialize state
            [](unit_t &) {
                // nop
            },
            // processing step
            [](unit_t &, downstream<int32_t> &out, int32_t x) { out.push(x); },
            // cleanup
            [=](unit_t &, const error &) { BOOST_TEST_MESSAGE(self->name() << " is done"); });
        return {
            [=](join_atom) {
                BOOST_TEST_MESSAGE("received 'join' request");
                return self->state.stage->add_outbound_path(std::make_tuple("numbers.txt"));
            },
            [=](const stream<int32_t> &in, std::string &fname) {
                BOOST_CHECK_EQUAL(fname, "numbers.txt");
                return self->state.stage->add_inbound_path(in);
            },
            [=](close_atom, int32_t sink_index) {
                auto &out = self->state.stage->out();
                out.close(out.path_slots().at(static_cast<size_t>(sink_index)));
            },
        };
    }

    using fixture = test_coordinator_fixture<>;

}    // namespace

// -- unit tests ---------------------------------------------------------------

BOOST_FIXTURE_TEST_SUITE(local_streaming_tests, fixture)

BOOST_AUTO_TEST_CASE(depth_3_pipeline_with_fork) {
    auto src = sys.spawn(file_reader, 50u);
    auto stg = sys.spawn(stream_multiplexer);
    auto snk1 = sys.spawn(sum_up);
    auto snk2 = sys.spawn(sum_up);
    auto &st = deref<stream_multiplexer_actor>(stg).state;
    BOOST_TEST_MESSAGE("connect sinks to the stage (fork)");
    self->send(snk1, join_atom_v, stg);
    self->send(snk2, join_atom_v, stg);
    consume_messages();
    BOOST_CHECK_EQUAL(st.stage->out().num_paths(), 2u);
    BOOST_TEST_MESSAGE("connect source to the stage (fork)");
    self->send(stg * src, "numbers.txt");
    consume_messages();
    BOOST_CHECK_EQUAL(st.stage->out().num_paths(), 2u);
    BOOST_CHECK_EQUAL(st.stage->inbound_paths().size(), 1u);
    run();
    BOOST_CHECK_EQUAL(st.stage->out().num_paths(), 2u);
    BOOST_CHECK_EQUAL(st.stage->inbound_paths().size(), 0u);
    BOOST_CHECK_EQUAL(deref<sum_up_actor>(snk1).state.x, 1275);
    BOOST_CHECK_EQUAL(deref<sum_up_actor>(snk2).state.x, 1275);
    self->send_exit(stg, exit_reason::kill);
}

BOOST_AUTO_TEST_CASE(depth_3_pipeline_with_join) {
    auto src1 = sys.spawn(file_reader, 50u);
    auto src2 = sys.spawn(file_reader, 50u);
    auto stg = sys.spawn(stream_multiplexer);
    auto snk = sys.spawn(sum_up);
    auto &st = deref<stream_multiplexer_actor>(stg).state;
    BOOST_TEST_MESSAGE("connect sink to the stage");
    self->send(snk, join_atom_v, stg);
    consume_messages();
    BOOST_CHECK_EQUAL(st.stage->out().num_paths(), 1u);
    BOOST_TEST_MESSAGE("connect sources to the stage (join)");
    self->send(stg * src1, "numbers.txt");
    self->send(stg * src2, "numbers.txt");
    consume_messages();
    BOOST_CHECK_EQUAL(st.stage->out().num_paths(), 1u);
    BOOST_CHECK_EQUAL(st.stage->inbound_paths().size(), 2u);
    run();
    BOOST_CHECK_EQUAL(st.stage->out().num_paths(), 1u);
    BOOST_CHECK_EQUAL(st.stage->inbound_paths().size(), 0u);
    BOOST_CHECK_EQUAL(deref<sum_up_actor>(snk).state.x, 2550);
    self->send_exit(stg, exit_reason::kill);
}

BOOST_AUTO_TEST_CASE(closing_downstreams_before_end_of_stream) {
    auto src = sys.spawn(file_reader, 10000u);
    auto stg = sys.spawn(stream_multiplexer);
    auto snk1 = sys.spawn(sum_up);
    auto snk2 = sys.spawn(sum_up);
    auto &st = deref<stream_multiplexer_actor>(stg).state;
    BOOST_TEST_MESSAGE("connect sinks to the stage (fork)");
    self->send(snk1, join_atom_v, stg);
    self->send(snk2, join_atom_v, stg);
    consume_messages();
    BOOST_CHECK_EQUAL(st.stage->out().num_paths(), 2u);
    BOOST_TEST_MESSAGE("connect source to the stage (fork)");
    self->send(stg * src, "numbers.txt");
    consume_messages();
    BOOST_CHECK_EQUAL(st.stage->out().num_paths(), 2u);
    BOOST_CHECK_EQUAL(st.stage->inbound_paths().size(), 1u);
    BOOST_TEST_MESSAGE("do a single round of credit");
    trigger_timeouts();
    consume_messages();
    BOOST_TEST_MESSAGE("make sure the stream isn't done yet");
    BOOST_REQUIRE(!deref<file_reader_actor>(src).state.buf.empty());
    BOOST_CHECK_EQUAL(st.stage->out().num_paths(), 2u);
    BOOST_CHECK_EQUAL(st.stage->inbound_paths().size(), 1u);
    BOOST_TEST_MESSAGE("get the next not-yet-buffered integer");
    auto next_pending = deref<file_reader_actor>(src).state.buf.front();
    BOOST_REQUIRE_GT(next_pending, 0);
    auto sink1_result = sum(next_pending - 1);
    BOOST_TEST_MESSAGE("gracefully close sink 1, next pending: " << next_pending);
    self->send(stg, close_atom_v, 0);
    expect((close_atom, int32_t), from(self).to(stg));
    BOOST_TEST_MESSAGE("ship remaining elements");
    run();
    BOOST_CHECK_EQUAL(st.stage->out().num_paths(), 1u);
    BOOST_CHECK_EQUAL(st.stage->inbound_paths().size(), 0u);
    BOOST_CHECK_LT(deref<sum_up_actor>(snk1).state.x, sink1_result);
    BOOST_CHECK_EQUAL(deref<sum_up_actor>(snk2).state.x, sum(10000));
    self->send_exit(stg, exit_reason::kill);
}

BOOST_AUTO_TEST_SUITE_END()
