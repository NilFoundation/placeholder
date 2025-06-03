//---------------------------------------------------------------------------//
// Copyright (c) 2023 Martun Karapetyan <martun@nil.foundation>
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

#ifndef CRYPTO3_THREAD_POOL_HPP
#define CRYPTO3_THREAD_POOL_HPP

#include <sched.h>
#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>

#include <functional>
#include <future>
#include <thread>
#include <memory>
#include <stdexcept>


namespace nil {
    namespace crypto3 {

        class ThreadPool {
            public:
            static std::size_t core_count() {
#if defined(__linux__) && !defined(__ANDROID__)
                cpu_set_t cpuset;
                if (sched_getaffinity(0, sizeof(cpuset), &cpuset)) {
                    auto count = CPU_COUNT(&cpuset);
                    if (count != 0) {
                        return count;
                    }
                }
#endif
                return std::thread::hardware_concurrency();
            }
            enum class PoolLevel {
                LOW,
                HIGH
            };

            /** Returns a thread pool, based on the pool_id. pool with LOW is normally used for low-level operations, like polynomial
             *  operations and fft. Any code that uses these operations and needs to be parallel will submit its tasks to pool with HIGH.
             *  Submission of higher level tasks to low level pool will immediately result in a deadlock.
             */
            static ThreadPool& get_instance(PoolLevel pool_id) {
                static std::size_t pool_size = core_count();
                static ThreadPool instance_for_low_level(pool_size);
                static ThreadPool instance_for_middle_level(pool_size);

                if (pool_id == PoolLevel::LOW)
                    return instance_for_low_level;
                if (pool_id == PoolLevel::HIGH)
                    return instance_for_middle_level;
                throw std::invalid_argument("Invalid instance of thread pool requested.");
            }

            ThreadPool(const ThreadPool& obj)= delete;
            ThreadPool& operator=(const ThreadPool& obj)= delete;

            template<class ReturnType>
            inline std::future<ReturnType> post(std::function<ReturnType()> task) {
                auto packaged_task = std::make_shared<std::packaged_task<ReturnType()>>(std::move(task));
                std::future<ReturnType> fut = packaged_task->get_future();
                boost::asio::post(pool, [packaged_task]() -> void { (*packaged_task)(); });
                return fut;
            }

            // Waits for all the tasks to complete.
            inline void join() {
                pool.join();
            }

            std::size_t get_pool_size() const {
                return pool_size;
            }

        private:
            inline ThreadPool(std::size_t pool_size)
                : pool(pool_size)
                , pool_size(pool_size)  {
            }

            boost::asio::thread_pool pool;
            const std::size_t pool_size;

        };

    }        // namespace crypto3
}    // namespace nil

#endif // CRYPTO3_THREAD_POOL_HPP
