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

#include <thread>
#include <iostream>

#include <nil/actor/testing/entry_point.hh>
#include <nil/actor/testing/actor_test.hh>
#include <nil/actor/testing/test_runner.hh>
#include <nil/actor/core/future.hh>
#include <nil/actor/core/on_internal_error.hh>
#include <nil/actor/core/app_template.hh>
#include <nil/actor/testing/on_internal_error.hh>

namespace nil {
    namespace actor {

        namespace testing {

            exchanger_base::exchanger_base() {
            }
            exchanger_base::~exchanger_base() {
            }

            void actor_test::run() {
                // HACK: please see https://github.com/cloudius-systems/actor/issues/10
                BOOST_REQUIRE(true);

                // HACK: please see https://github.com/cloudius-systems/actor/issues/10
                boost::program_options::variables_map()["dummy"];

                set_abort_on_internal_error(true);

                global_test_runner().run_sync([this] { return run_test_case(); });
            }

            // We store a pointer because tests are registered from dynamic initializers,
            // so we must ensure that 'tests' is initialized before any dynamic initializer.
            // I use a primitive type, which is guaranteed to be initialized before any
            // dynamic initializer and lazily allocate the factor.

            static std::vector<actor_test *> *tests = nullptr;

            const std::vector<actor_test *> &known_tests() {
                if (!tests) {
                    throw std::runtime_error("No tests registered");
                }
                return *tests;
            }

            actor_test::actor_test() {
                if (!tests) {
                    tests = new std::vector<actor_test *>();
                }
                tests->push_back(this);
            }

            namespace exception_predicate {

                std::function<bool(const std::exception &)> message_equals(std::string_view expected_message) {
                    return [expected_message](const std::exception &e) {
                        std::string error = e.what();
                        if (error == expected_message) {
                            return true;
                        } else {
                            std::cerr << "Expected \"" << expected_message << "\" but got \"" << error << '"'
                                      << std::endl;
                            return false;
                        }
                    };
                }

                std::function<bool(const std::exception &)> message_contains(std::string_view expected_message) {
                    return [expected_message](const std::exception &e) {
                        std::string error = e.what();
                        if (error.find(expected_message.data()) != std::string::npos) {
                            return true;
                        } else {
                            std::cerr << "Expected \"" << expected_message << "\" but got \"" << error << '"'
                                      << std::endl;
                            return false;
                        }
                    };
                }

            }    // namespace exception_predicate

            scoped_no_abort_on_internal_error::scoped_no_abort_on_internal_error() {
                set_abort_on_internal_error(false);
            }

            scoped_no_abort_on_internal_error::~scoped_no_abort_on_internal_error() {
                set_abort_on_internal_error(true);
            }

        }    // namespace testing

    }    // namespace actor
}    // namespace nil
