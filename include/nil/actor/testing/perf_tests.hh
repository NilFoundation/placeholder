//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#pragma once

#include <atomic>
#include <memory>

#include <fmt/format.h>

#include <nil/actor/core/future.hh>
#include <nil/actor/core/loop.hh>

using namespace nil::actor;

namespace perf_tests {
    namespace detail {

        struct config;

        using clock_type = std::chrono::steady_clock;

        class performance_test {
            std::string _test_case;
            std::string _test_group;

            uint64_t _single_run_iterations = 0;
            std::atomic<uint64_t> _max_single_run_iterations;

        private:
            void do_run(const config &);

        protected:
            [[gnu::always_inline]] [[gnu::hot]] bool stop_iteration() const {
                return _single_run_iterations >= _max_single_run_iterations.load(std::memory_order_relaxed);
            }

            [[gnu::always_inline]] [[gnu::hot]] void next_iteration(size_t n) {
                _single_run_iterations += n;
            }

            virtual void set_up() = 0;
            virtual void tear_down() noexcept = 0;
            virtual future<clock_type::duration> do_single_run() = 0;

        public:
            performance_test(const std::string &test_case, const std::string &test_group) :
                _test_case(test_case), _test_group(test_group) {
            }

            virtual ~performance_test() = default;

            const std::string &test_case() const {
                return _test_case;
            }
            const std::string &test_group() const {
                return _test_group;
            }
            std::string name() const {
                return fmt::format("{}.{}", test_group(), test_case());
            }

            void run(const config &);

        public:
            static void register_test(std::unique_ptr<performance_test>);
        };

        // Helper for measuring time.
        // Each microbenchmark can either use the default behaviour which measures
        // only the start and stop time of the whole run or manually invoke
        // start_measuring_time() and stop_measuring_time() in order to measure
        // only parts of each iteration.
        class time_measurement {
            clock_type::time_point _run_start_time;
            clock_type::time_point _start_time;
            clock_type::duration _total_time;

        public:
            [[gnu::always_inline]] [[gnu::hot]] void start_run() {
                _total_time = {};
                auto t = clock_type::now();
                _run_start_time = t;
                _start_time = t;
            }

            [[gnu::always_inline]] [[gnu::hot]] clock_type::duration stop_run() {
                auto t = clock_type::now();
                if (_start_time == _run_start_time) {
                    return t - _start_time;
                }
                return _total_time;
            }

            [[gnu::always_inline]] [[gnu::hot]] void start_iteration() {
                _start_time = clock_type::now();
            }

            [[gnu::always_inline]] [[gnu::hot]] void stop_iteration() {
                auto t = clock_type::now();
                _total_time += t - _start_time;
            }
        };

        extern time_measurement measure_time;

        namespace {

            template<bool Condition, typename TrueFn, typename FalseFn>
            struct do_if_constexpr_ : FalseFn {
                do_if_constexpr_(TrueFn, FalseFn false_fn) : FalseFn(std::move(false_fn)) {
                }
                decltype(auto) operator()() const {
                    // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=64095
                    return FalseFn::operator()(0);
                }
            };
            template<typename TrueFn, typename FalseFn>
            struct do_if_constexpr_<true, TrueFn, FalseFn> : TrueFn {
                do_if_constexpr_(TrueFn true_fn, FalseFn) : TrueFn(std::move(true_fn)) {
                }
                decltype(auto) operator()() const {
                    return TrueFn::operator()(0);
                }
            };

            template<bool Condition, typename TrueFn, typename FalseFn>
            do_if_constexpr_<Condition, TrueFn, FalseFn> if_constexpr_(TrueFn &&true_fn, FalseFn &&false_fn) {
                return do_if_constexpr_<Condition, TrueFn, FalseFn>(std::forward<TrueFn>(true_fn),
                                                                    std::forward<FalseFn>(false_fn));
            }

        }    // namespace

        template<typename Test>
        class concrete_performance_test final : public performance_test {
            boost::optional<Test> _test;

        private:
            template<typename... Args>
            auto run_test(Args &&...) {
                return _test->run();
            }

        protected:
            virtual void set_up() override {
                _test.emplace();
            }

            virtual void tear_down() noexcept override {
                _test = boost::none;
            }

            [[gnu::hot]] virtual future<clock_type::duration> do_single_run() override {
                // Redundant 'this->'s courtesy of https://gcc.gnu.org/bugzilla/show_bug.cgi?id=61636
                return if_constexpr_<is_future<decltype(_test->run())>::value>(
                    [&](auto &&...) {
                        measure_time.start_run();
                        return do_until([this] { return this->stop_iteration(); },
                                        [this] {
                                            return if_constexpr_<std::is_same<decltype(_test->run()), future<>>::value>(
                                                [&](auto &&...) {
                                                    this->next_iteration(1);
                                                    return _test->run();
                                                },
                                                [&](auto &&...dependency) {
                                                    // We need `dependency` to make sure the compiler won't be able to
                                                    // instantiate anything (and notice that the code does not compile)
                                                    // if this part of if_constexpr_ is not active.
                                                    return run_test(dependency...).then([&](size_t n) {
                                                        this->next_iteration(n);
                                                    });
                                                })();
                                        })
                            .then([] { return measure_time.stop_run(); });
                    },
                    [&](auto &&...) {
                        measure_time.start_run();
                        while (!stop_iteration()) {
                            if_constexpr_<std::is_void<decltype(_test->run())>::value>(
                                [&](auto &&...) {
                                    (void)_test->run();
                                    this->next_iteration(1);
                                },
                                [&](auto &&...dependency) {
                                    // We need `dependency` to make sure the compiler won't be able to instantiate
                                    // anything (and notice that the code does not compile) if this part of
                                    // if_constexpr_ is not active.
                                    this->next_iteration(run_test(dependency...));
                                })();
                        }
                        return make_ready_future<clock_type::duration>(measure_time.stop_run());
                    })();
            }

        public:
            using performance_test::performance_test;
        };

        void register_test(std::unique_ptr<performance_test>);

        template<typename Test>
        struct test_registrar {
            test_registrar(const std::string &test_group, const std::string &test_case) {
                auto test = std::make_unique<concrete_performance_test<Test>>(test_case, test_group);
                performance_test::register_test(std::move(test));
            }
        };

    }    // namespace detail

    [[gnu::always_inline]] inline void start_measuring_time() {
        detail::measure_time.start_iteration();
    }

    [[gnu::always_inline]] inline void stop_measuring_time() {
        detail::measure_time.stop_iteration();
    }

    template<typename T>
    void do_not_optimize(const T &v) {
        asm volatile("" : : "r,m"(v));
    }

}    // namespace perf_tests

// PERF_TEST and PERF_TEST_F support both synchronous and asynchronous functions.
// The former should return `void`, the latter `future<>`.
//
// Test cases may perform multiple operations in a single run, this may be desirable
// if the cost of an individual operation is very small. This allows measuring either
// the latency of throughput depending on how the test in written. In such cases,
// the test function shall return either size_t or future<size_t> for synchronous and
// asynchronous cases respectively. The returned value shall be the number of iterations
// done in a single test run.

#define PERF_TEST_F(test_group, test_case)                                       \
    struct test_##test_group##_##test_case : test_group {                        \
        [[gnu::always_inline]] inline auto run();                                \
    };                                                                           \
    static ::perf_tests::detail::test_registrar<test_##test_group##_##test_case> \
        test_##test_group##_##test_case##_registrar(#test_group, #test_case);    \
    [[gnu::always_inline]] auto test_##test_group##_##test_case::run()

#define PERF_TEST(test_group, test_case)                                         \
    struct test_##test_group##_##test_case {                                     \
        [[gnu::always_inline]] inline auto run();                                \
    };                                                                           \
    static ::perf_tests::detail::test_registrar<test_##test_group##_##test_case> \
        test_##test_group##_##test_case##_registrar(#test_group, #test_case);    \
    [[gnu::always_inline]] auto test_##test_group##_##test_case::run()
