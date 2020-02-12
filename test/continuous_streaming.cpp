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

#define BOOST_TEST_MODULE continuous_streaming_test

#include <memory>
#include <numeric>

#include <nil/actor/test/dsl.hpp>

#include <nil/actor/spawner.hpp>
#include <nil/actor/spawner_config.hpp>
#include <nil/actor/event_based_actor.hpp>
#include <nil/actor/stateful_actor.hpp>

#include <nil/actor/spawner_config.hpp>

using std::string;

using namespace nil::actor;

namespace {

    /// Returns the sum of natural numbers up until `n`, i.e., 1 + 2 + ... + n.
    int sum(int n) {
        return (n * (n + 1)) / 2;
    }

    TESTEE_SETUP();

    TESTEE_STATE(file_reader) {
        std::vector<int> buf;
    };

    VARARGS_TESTEE(file_reader, size_t buf_size) {
        return {[=](string &fname) -> output_stream<int, string> {
            BOOST_CHECK_EQUAL(fname, "numbers.txt");
            BOOST_CHECK_EQUAL(self->mailbox().empty(), true);
            return self->make_source(
                // forward file name in handshake to next stage
                std::forward_as_tuple(std::move(fname)),
                // initialize state
                [=](unit_t &) {
                    auto &xs = self->state.buf;
                    xs.resize(buf_size);
                    std::iota(xs.begin(), xs.end(), 1);
                },
                // get next element
                [=](unit_t &, downstream<int> &out, size_t num) {
                    auto &xs = self->state.buf;
                    BOOST_TEST_MESSAGE("push " << num << " messages downstream");
                    auto n = std::min(num, xs.size());
                    for (size_t i = 0; i < n; ++i) {
                        out.push(xs[i]);
                    }
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
        int x = 0;
    };

    TESTEE(sum_up) {
        return {[=](stream<int> &in, const string &fname) {
                    BOOST_CHECK_EQUAL(fname, "numbers.txt");
                    using int_ptr = int *;
                    return self->make_sink(
                        // input stream
                        in,
                        // initialize state
                        [=](int_ptr &x) { x = &self->state.x; },
                        // processing step
                        [](int_ptr &x, int y) { *x += y; },
                        // cleanup
                        [=](int_ptr &, const error &) { BOOST_TEST_MESSAGE(self->name() << " is done"); });
                },
                [=](join_atom atm, actor src) {
                    BOOST_TEST_MESSAGE(self->name() << " joins a stream");
                    self->send(self * src, atm);
                }};
    }

    TESTEE_STATE(stream_multiplexer) {
        stream_stage_ptr<int, broadcast_downstream_manager<int>> stage;
    };

    TESTEE(stream_multiplexer) {
        self->state.stage = self->make_continuous_stage(
            // initialize state
            [](unit_t &) {
                // nop
            },
            // processing step
            [](unit_t &, downstream<int> &out, int x) { out.push(x); },
            // cleanup
            [=](unit_t &, const error &) { BOOST_TEST_MESSAGE(self->name() << " is done"); });
        return {
            [=](join_atom) {
                BOOST_TEST_MESSAGE("received 'join' request");
                return self->state.stage->add_outbound_path(std::make_tuple("numbers.txt"));
            },
            [=](const stream<int> &in, std::string &fname) {
                BOOST_CHECK_EQUAL(fname, "numbers.txt");
                return self->state.stage->add_inbound_path(in);
            },
            [=](close_atom, int sink_index) {
                auto &out = self->state.stage->out();
                out.close(out.path_slots().at(static_cast<size_t>(sink_index)));
            },
        };
    }

    using fixture = test_coordinator_fixture<>;

}    // namespace

// -- unit tests ---------------------------------------------------------------

BOOST_FIXTURE_TEST_SUITE(local_streaming_tests, fixture)

BOOST_AUTO_TEST_CASE(depth_3_pipeline_with_fork_test) {
    auto src = sys.spawn(file_reader, 50u);
    auto stg = sys.spawn(stream_multiplexer);
    auto snk1 = sys.spawn(sum_up);
    auto snk2 = sys.spawn(sum_up);
    auto &st = deref<stream_multiplexer_actor>(stg).state;
    BOOST_TEST_MESSAGE("connect sinks to the stage (fork)");
    self->send(snk1, join_atom::value, stg);
    self->send(snk2, join_atom::value, stg);
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

BOOST_AUTO_TEST_CASE(depth_3_pipeline_with_join_test) {
    auto src1 = sys.spawn(file_reader, 50u);
    auto src2 = sys.spawn(file_reader, 50u);
    auto stg = sys.spawn(stream_multiplexer);
    auto snk = sys.spawn(sum_up);
    auto &st = deref<stream_multiplexer_actor>(stg).state;
    BOOST_TEST_MESSAGE("connect sink to the stage");
    self->send(snk, join_atom::value, stg);
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

BOOST_AUTO_TEST_CASE(closing_downstreams_before_end_of_stream_test) {
    auto src = sys.spawn(file_reader, 10000u);
    auto stg = sys.spawn(stream_multiplexer);
    auto snk1 = sys.spawn(sum_up);
    auto snk2 = sys.spawn(sum_up);
    auto &st = deref<stream_multiplexer_actor>(stg).state;
    BOOST_TEST_MESSAGE("connect sinks to the stage (fork)");
    self->send(snk1, join_atom::value, stg);
    self->send(snk2, join_atom::value, stg);
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
    self->send(stg, close_atom::value, 0);
    expect((atom_value, int), from(self).to(stg));
    BOOST_TEST_MESSAGE("ship remaining elements");
    run();
    BOOST_CHECK_EQUAL(st.stage->out().num_paths(), 1u);
    BOOST_CHECK_EQUAL(st.stage->inbound_paths().size(), 0u);
    BOOST_CHECK_LT(deref<sum_up_actor>(snk1).state.x, sink1_result);
    BOOST_CHECK_EQUAL(deref<sum_up_actor>(snk2).state.x, sum(10000));
    self->send_exit(stg, exit_reason::kill);
}

BOOST_AUTO_TEST_SUITE_END()
