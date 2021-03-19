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

#include <nil/actor/testing/entry_point.hh>
#include <nil/actor/testing/actor_test.hh>
#include <nil/actor/testing/test_runner.hh>

namespace nil {
    namespace actor {
        namespace testing {

            static bool init_unit_test_suite() {
                const auto &tests = known_tests();
                auto &&ts = boost::unit_test::framework::master_test_suite();
                ts.p_name.set(tests.size() ? (tests)[0]->get_test_file() : "seastar-tests");

                for (seastar_test *test : tests) {
#if BOOST_VERSION > 105800
                    ts.add(boost::unit_test::make_test_case([test] { test->run(); }, test->get_name(),
                                                            test->get_test_file(), 0),
                           test->get_expected_failures(), 0);
#else
                    ts.add(boost::unit_test::make_test_case([test] { test->run(); }, test->get_name()),
                           test->get_expected_failures(), 0);
#endif
                }

                return global_test_runner().start(ts.argc, ts.argv);
            }

            static void dummy_handler(int) {
                // This handler should have been replaced.
                _exit(1);
            }

            static void install_dummy_handler(int sig) {
                struct sigaction sa;
                sa.sa_handler = dummy_handler;
                sigaction(sig, &sa, nullptr);
            }

            int entry_point(int argc, char **argv) {
#ifndef ACTOR_ASAN_ENABLED
                // Before we call into boost, install some dummy signal
                // handlers. This seems to be the only way to stop boost from
                // installing its own handlers, which disables our backtrace
                // printer. The real handler will be installed when the reactor is
                // constructed.
                // If we are using ASAN, it has already installed a signal handler
                // that does its own stack printing.
                for (int sig : {SIGSEGV, SIGABRT}) {
                    install_dummy_handler(sig);
                }
#else
                (void)install_dummy_handler;
#endif

                const int boost_exit_code = ::boost::unit_test::unit_test_main(&init_unit_test_suite, argc, argv);
                const int seastar_exit_code = nil::actor::testing::global_test_runner().finalize();

                return boost_exit_code ? boost_exit_code : seastar_exit_code;
            }
        }    // namespace testing
    }        // namespace actor
}    // namespace nil
