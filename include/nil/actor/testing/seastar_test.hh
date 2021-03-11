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

#include <vector>

#include <boost/test/unit_test.hpp>

#include <nil/actor/core/future.hh>
#include <nil/actor/detail/std-compat.hh>

#include <nil/actor/testing/entry_point.hh>

namespace nil {
    namespace actor {

        namespace testing {

            class BOOST_SYMBOL_EXPORT seastar_test {
            public:
                seastar_test();
                virtual ~seastar_test() {
                }
                virtual const char *get_test_file() = 0;
                virtual const char *get_name() = 0;
                virtual int get_expected_failures() {
                    return 0;
                }
                virtual future<> run_test_case() = 0;
                void run();
            };

            const std::vector<seastar_test *> &known_tests();

            // BOOST_REQUIRE_EXCEPTION predicates
            namespace exception_predicate {

                std::function<bool(const std::exception &)> message_equals(std::string_view expected_message);
                std::function<bool(const std::exception &)> message_contains(std::string_view expected_message);

            }    // namespace exception_predicate

        }    // namespace testing

    }    // namespace actor
}    // namespace nil

#ifdef ACTOR_TESTING_MAIN

int main(int argc, char **argv) {
    return nil::actor::testing::entry_point(argc, argv);
}

#endif    // ACTOR_TESTING_MAIN
