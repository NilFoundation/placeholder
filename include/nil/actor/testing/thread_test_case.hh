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

#include <nil/actor/core/future.hh>
#include <nil/actor/core/thread.hh>

#include <nil/actor/testing/seastar_test.hh>

#define ACTOR_THREAD_TEST_CASE_EXPECTED_FAILURES(name, failures)    \
    struct name : public nil::actor::testing::seastar_test {          \
        const char *get_test_file() override {                        \
            return __FILE__;                                          \
        }                                                             \
        const char *get_name() override {                             \
            return #name;                                             \
        }                                                             \
        int get_expected_failures() override {                        \
            return failures;                                          \
        }                                                             \
        nil::actor::future<> run_test_case() override {               \
            return nil::actor::async([this] { do_run_test_case(); }); \
        }                                                             \
        void do_run_test_case();                                      \
    };                                                                \
    static name name##_instance;                                      \
    void name::do_run_test_case()

#define ACTOR_THREAD_TEST_CASE(name) ACTOR_THREAD_TEST_CASE_EXPECTED_FAILURES(name, 0)
