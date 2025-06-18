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

#ifndef CRYPTO3_PARALLELIZATION_UTILS_HPP
#define CRYPTO3_PARALLELIZATION_UTILS_HPP

#include <future>
#include <vector>

#include <nil/actor/core/thread_pool.hpp>

namespace nil {
    namespace crypto3 {

        template<class ReturnType>
        std::vector<ReturnType> wait_for_all(std::vector<std::future<ReturnType>> futures) {
            std::vector<ReturnType> results;
            for (auto& f: futures) {
                results.push_back(f.get());
            }
            return results;
        }

        inline void wait_for_all(std::vector<std::future<void>> futures) {
            for (auto& f: futures) {
                f.get();
            }
        }

        // Divides work into chunks and makes calls to 'func' in parallel.
        template<class ReturnType>
        std::vector<std::future<ReturnType>> parallel_run_in_chunks_with_thread_id(
                std::size_t elements_count,
                std::function<ReturnType(std::size_t thread_id, std::size_t begin, std::size_t end)> func,
                ThreadPool::PoolLevel pool_id = ThreadPool::PoolLevel::LOW) {

            auto& thread_pool = ThreadPool::get_instance(pool_id);

            std::vector<std::future<ReturnType>> fut;
            std::size_t workers_to_use = std::max((size_t)1, std::min(elements_count, thread_pool.get_pool_size()));

            // For pool #0 we have experimentally found that operations over chunks of <4096 elements
            // do not load the cores. In case we have smaller chunks, it's better to load less cores.
            static constexpr std::size_t POOL_0_MIN_CHUNK_SIZE = 1 << 12;

            // Pool #0 will take care of the lowest level of operations, like polynomial operations.
            // We want the minimal size of elements_per_worker to be 'POOL_0_MIN_CHUNK_SIZE', otherwise the cores are not loaded.
            if (pool_id == ThreadPool::PoolLevel::LOW && elements_count / workers_to_use < POOL_0_MIN_CHUNK_SIZE) {
                workers_to_use = elements_count / POOL_0_MIN_CHUNK_SIZE + ((elements_count % POOL_0_MIN_CHUNK_SIZE) ? 1 : 0);
                workers_to_use = std::max((size_t)1, workers_to_use);
            }

            std::size_t begin = 0;
            for (std::size_t i = 0; i < workers_to_use; i++) {
                auto end = begin + (elements_count - begin) / (workers_to_use - i);
                fut.emplace_back(thread_pool.post<ReturnType>([i, begin, end, func]() {
                    return func(i, begin, end);
                }));
                begin = end;
            }
            return fut;
        }

        template<class ReturnType>
        std::vector<std::future<ReturnType>> parallel_run_in_chunks(
                std::size_t elements_count,
                std::function<ReturnType(std::size_t begin, std::size_t end)> func,
                ThreadPool::PoolLevel pool_id = ThreadPool::PoolLevel::LOW) {
            return parallel_run_in_chunks_with_thread_id<ReturnType>(elements_count,
                [func](std::size_t thread_id, std::size_t begin, std::size_t end) -> ReturnType {
                    return func(begin, end);
                }, pool_id);
        }

        // Similar to std::transform, but in parallel. We return void here for better usability for our use cases.
        template<class InputIt1, class InputIt2, class OutputIt, class BinaryOperation>
        void parallel_transform(InputIt1 first1, InputIt1 last1, InputIt2 first2,
                                OutputIt d_first, BinaryOperation binary_op,
                                ThreadPool::PoolLevel pool_id = ThreadPool::PoolLevel::LOW) {

            wait_for_all(parallel_run_in_chunks<void>(
                std::distance(first1, last1),
                // We need the lambda to be mutable, to be able to modify iterators captured by value.
                [first1, last1, first2, d_first, binary_op](std::size_t begin, std::size_t end) mutable {
                    std::advance(first1, begin);
                    std::advance(first2, begin);
                    std::advance(d_first, begin);
                    for (std::size_t i = begin; i < end && first1 != last1; i++) {
                        *d_first = binary_op(*first1, *first2);
                        ++first1;
                        ++first2;
                        ++d_first;
                    }
                }, pool_id));
        }

        // Similar to std::transform, but in parallel. We return void here for better usability for our use cases.
        template<class InputIt, class OutputIt, class UnaryOperation>
        void parallel_transform(InputIt first1, InputIt last1,
                                OutputIt d_first, UnaryOperation unary_op,
                                ThreadPool::PoolLevel pool_id = ThreadPool::PoolLevel::LOW) {

            wait_for_all(parallel_run_in_chunks<void>(
                std::distance(first1, last1),
                // We need the lambda to be mutable, to be able to modify iterators captured by value.
                [first1, last1, d_first, unary_op](std::size_t begin, std::size_t end) mutable {
                    std::advance(first1, begin);
                    std::advance(d_first, begin);
                    for (std::size_t i = begin; i < end && first1 != last1; i++) {
                        *d_first = unary_op(*first1);
                        ++first1;
                        ++d_first;
                    }
                }, pool_id));
        }

        // This one is an optimization, since copying field elements is quite slow.
        // BinaryOperation is supposed to modify the object in-place.
        template<class InputIt1, class InputIt2, class BinaryOperation>
        void in_place_parallel_transform(InputIt1 first1, InputIt1 last1, InputIt2 first2,
                                         BinaryOperation binary_op,
                                         ThreadPool::PoolLevel pool_id = ThreadPool::PoolLevel::LOW) {

            wait_for_all(parallel_run_in_chunks<void>(
                std::distance(first1, last1),
                // We need the lambda to be mutable, to be able to modify iterators captured by value.
                [first1, last1, first2, binary_op](std::size_t begin, std::size_t end) mutable {
                    std::advance(first1, begin);
                    std::advance(first2, begin);
                    for (std::size_t i = begin; i < end && first1 != last1; i++) {
                        binary_op(*first1, *first2);
                        ++first1;
                        ++first2;
                    }
                }, pool_id));
        }

        // This one is an optimization, since copying field elements is quite slow.
        // UnaryOperation is supposed to modify the object in-place.
        template<class InputIt, class UnaryOperation>
        void parallel_foreach(InputIt first1, InputIt last1, UnaryOperation unary_op,
                              ThreadPool::PoolLevel pool_id = ThreadPool::PoolLevel::LOW) {

            wait_for_all(parallel_run_in_chunks<void>(
                std::distance(first1, last1),
                // We need the lambda to be mutable, to be able to modify iterators captured by value.
                [first1, last1, unary_op](std::size_t begin, std::size_t end) mutable {
                    std::advance(first1, begin);
                    for (std::size_t i = begin; i < end && first1 != last1; i++) {
                        unary_op(*first1);
                        ++first1;
                    }
                }, pool_id));
        }

        // Calls function func for each value between [start, end).
        inline void parallel_for(std::size_t start, std::size_t end, std::function<void(std::size_t index)> func,
                                 ThreadPool::PoolLevel pool_id = ThreadPool::PoolLevel::LOW) {
            wait_for_all(parallel_run_in_chunks<void>(
                end - start,
                [start, func](std::size_t range_begin, std::size_t range_end) {
                    for (std::size_t i = start + range_begin; i < start + range_end; i++) {
                        func(i);
                    }
                }, pool_id));
        }

    }        // namespace crypto3
}    // namespace nil

#endif // CRYPTO3_PARALLELIZATION_UTILS_HPP
