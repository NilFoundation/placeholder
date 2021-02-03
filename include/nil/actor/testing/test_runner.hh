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

#include <memory>
#include <functional>
#include <atomic>
#include <random>

#include <nil/actor/core/future.hh>
#include <nil/actor/core/posix.hh>
#include <nil/actor/testing/exchanger.hh>
#include <nil/actor/testing/random.hh>

namespace nil {
    namespace actor {

        namespace testing {

            class test_runner {
            private:
                std::unique_ptr<posix_thread> _thread;
                std::atomic<bool> _started {false};
                exchanger<std::function<future<>()>> _task;
                bool _done = false;
                int _exit_code {0};

            public:
                // Returns whether initialization was successful.
                // Will return as soon as the nil::actor::app was started.
                bool start(int argc, char **argv);
                ~test_runner();
                void run_sync(std::function<future<>()> task);
                // Returns the return value of the underlying `nil::actor::app::run()`.
                int finalize();
            };

            test_runner &global_test_runner();

        }    // namespace testing

    }    // namespace actor
}    // namespace nil
