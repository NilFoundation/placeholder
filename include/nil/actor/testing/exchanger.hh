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

#include <mutex>
#include <condition_variable>

#include <nil/actor/detail/std-compat.hh>

namespace nil {
    namespace actor {

        namespace testing {

            class exchanger_base {
            protected:
                exchanger_base();
                ~exchanger_base();
                std::mutex _mutex;
                std::condition_variable _cv;
                std::exception_ptr _exception;
                void interrupt_ptr(std::exception_ptr e) {
                    std::unique_lock<std::mutex> lock(_mutex);
                    if (!_exception) {
                        _exception = e;
                        _cv.notify_all();
                    }
                    // FIXME: log if already interrupted
                }
            };

            // Single-element blocking queue
            template<typename T>
            class exchanger : public exchanger_base {
            private:
                boost::optional<T> _element;

            public:
                template<typename Exception>
                void interrupt(Exception e) {
                    try {
                        throw e;
                    } catch (...) {
                        interrupt_ptr(std::current_exception());
                    }
                }
                void give(T value) {
                    std::unique_lock<std::mutex> lock(_mutex);
                    _cv.wait(lock, [this] { return !_element || _exception; });
                    if (_exception) {
                        std::rethrow_exception(_exception);
                    }
                    _element = value;
                    _cv.notify_one();
                }
                T take() {
                    std::unique_lock<std::mutex> lock(_mutex);
                    _cv.wait(lock, [this] { return bool(_element) || _exception; });
                    if (_exception) {
                        std::rethrow_exception(_exception);
                    }
                    auto v = *_element;
                    _element = {};
                    _cv.notify_one();
                    return v;
                }
            };

        }    // namespace testing

    }    // namespace actor
}    // namespace nil
