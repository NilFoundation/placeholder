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

#include <iostream>

#include <nil/actor/core/app-template.hh>
#include <nil/actor/core/reactor.hh>
#include <nil/actor/core/posix.hh>
#include <nil/actor/testing/test_runner.hh>

namespace nil {
    namespace actor {

        namespace testing {

            static test_runner instance;

            struct stop_execution : public std::exception { };

            test_runner::~test_runner() {
                finalize();
            }

            bool test_runner::start(int ac, char **av) {
                bool expected = false;
                if (!_started.compare_exchange_strong(expected, true, std::memory_order_acquire)) {
                    return true;
                }

                // Don't interfere with seastar signal handling
                sigset_t mask;
                sigfillset(&mask);
                for (auto sig : {SIGSEGV}) {
                    sigdelset(&mask, sig);
                }
                auto r = ::pthread_sigmask(SIG_BLOCK, &mask, NULL);
                if (r) {
                    std::cerr << "Error blocking signals. Aborting." << std::endl;
                    abort();
                }

                auto init_outcome = std::make_shared<exchanger<bool>>();

                _thread = std::make_unique<posix_thread>([this, ac, av, init_outcome]() mutable {
                    app_template app;
                    app.add_options()("random-seed", boost::program_options::value<unsigned>(),
                                      "Random number generator seed")(
                        "fail-on-abandoned-failed-futures", boost::program_options::value<bool>()->default_value(true),
                        "Fail the test if there are any abandoned failed futures");
                    // We guarantee that only one thread is running.
                    // We only read this after that one thread is joined, so this is safe.
                    _exit_code = app.run(ac, av, [this, &app, init_outcome = init_outcome.get()] {
                        init_outcome->give(true);
                        auto init = [&app] {
                            auto conf_seed = app.configuration()["random-seed"];
                            auto seed = conf_seed.empty() ? std::random_device()() : conf_seed.as<unsigned>();
                            std::cout << "random-seed=" << seed << '\n';
                            return smp::invoke_on_all([seed] {
                                auto local_seed = seed + this_shard_id();
                                local_random_engine.seed(local_seed);
                            });
                        };

                        return init()
                            .then([this] {
                                return do_until([this] { return _done; },
                                                [this] {
                                                    // this will block the reactor briefly, but we don't care
                                                    try {
                                                        auto func = _task.take();
                                                        return func();
                                                    } catch (const stop_execution &) {
                                                        _done = true;
                                                        return make_ready_future<>();
                                                    }
                                                })
                                    .or_terminate();
                            })
                            .then([&app] {
                                if (engine().abandoned_failed_futures()) {
                                    std::cerr << "*** " << engine().abandoned_failed_futures()
                                              << " abandoned failed future(s) detected\n";
                                    if (app.configuration()["fail-on-abandoned-failed-futures"].as<bool>()) {
                                        std::cerr << "Failing the test because fail was requested by "
                                                     "--fail-on-abandoned-failed-futures\n";
                                        return 3;
                                    }
                                }
                                return 0;
                            });
                    });
                    init_outcome->give(!_exit_code);
                });

                return init_outcome->take();
            }

            void test_runner::run_sync(std::function<future<>()> task) {
                exchanger<std::exception_ptr> e;
                _task.give([task = std::move(task), &e] {
                    try {
                        return task().then_wrapped([&e](auto &&f) {
                            try {
                                f.get();
                                e.give({});
                            } catch (...) {
                                e.give(std::current_exception());
                            }
                        });
                    } catch (...) {
                        e.give(std::current_exception());
                        return make_ready_future<>();
                    }
                });
                auto maybe_exception = e.take();
                if (maybe_exception) {
                    std::rethrow_exception(maybe_exception);
                }
            }

            int test_runner::finalize() {
                if (_thread) {
                    _task.interrupt(stop_execution());
                    _thread->join();
                    _thread = nullptr;
                }
                return _exit_code;
            }

            test_runner &global_test_runner() {
                return instance;
            }

        }    // namespace testing

    }    // namespace actor
}    // namespace nil
