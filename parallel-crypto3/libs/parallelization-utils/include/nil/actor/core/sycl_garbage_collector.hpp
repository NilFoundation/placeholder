//---------------------------------------------------------------------------//
// Copyright (c) 2025 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#ifdef GPU_PROVER

#ifndef PARALLEL_CRYPTO3_SYCL_GARBAGE_COLLECTOR_HPP
#define PARALLEL_CRYPTO3_SYCL_GARBAGE_COLLECTOR_HPP

#include <sycl/sycl.hpp>

#include <utility>
#include <unordered_map>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>

namespace nil {
    namespace actor {
        namespace core {
            template <typename T>
            T* device_malloc(std::size_t size, sycl::queue& queue) {
                T* ptr = nullptr;
                std::size_t num_tries = 0;
                while (ptr == nullptr) {
                    ptr = sycl::malloc_device<T>(size, queue);
                    if (ptr == nullptr) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                        num_tries++;
                    }
                    if (num_tries > 5000) {
                        std::cout << "No memory on GPU :(" << std::endl;
                        exit(1);
                    }
                }
                return ptr;
            }

            template <typename T>
            std::shared_ptr<T> make_shared_device_memory(std::size_t size, sycl::queue& queue) {
                T* ptr = device_malloc<T>(size, queue);
                return std::shared_ptr<T>(ptr, [queue](T* ptr) { sycl::free(ptr, queue); });
            }

            template <typename T>
            struct sycl_garbage_collector {
                sycl::queue queue;
                using event_finality_pair = std::pair<sycl::event, bool>;
                std::unordered_map<std::shared_ptr<T>, event_finality_pair> tracked_memory;
                std::mutex memory_mutex;
                std::thread garbage_collector_thread;
                std::atomic<bool> thread_running = true;

                const std::chrono::milliseconds sleep_time = std::chrono::milliseconds(10);

                sycl_garbage_collector(sycl::queue& queue) : queue(queue) {
                    garbage_collector_thread = std::thread([this]() {
                        while (thread_running.load()) {
                            {
                                std::lock_guard<std::mutex> lock(memory_mutex);
                                // clear all memory for which the event is complete and is final
                                std::erase_if(tracked_memory,
                                    [](const std::pair<std::shared_ptr<T>, event_finality_pair>& pair) {
                                        const auto& event = pair.second.first;
                                        const auto event_status = event.template get_info<sycl::info::event::command_execution_status>();
                                        const bool is_done = event_status == sycl::info::event_command_status::complete;
                                        const bool is_final = pair.second.second;
                                        return is_done && is_final;
                                });
                            }
                            std::this_thread::sleep_for(sleep_time);
                        }
                    });
                }

                void track_memory(std::shared_ptr<T> memory, sycl::event event, bool is_final = false) {
                    if (memory != nullptr) [[likely]] {
                        std::lock_guard<std::mutex> lock(memory_mutex);
                        tracked_memory[memory] = {event, is_final};
                    }
                }

                void track_memory(const T &memory, sycl::event event, bool is_final = false) {
                    sycl::queue& queue = this->queue;
                    track_memory(std::make_shared<T>(memory, [&queue](T* ptr) { sycl::free(ptr, queue); }), event, is_final);
                }

                void track_memory(T* memory, sycl::event event, bool is_final = false) {
                    sycl::queue& queue = this->queue;
                    if (memory != nullptr) {
                        track_memory(std::shared_ptr<T>(memory, [&queue](T* ptr) { sycl::free(ptr, queue); }), event, is_final);
                    }
                }

                void finalize_all() {
                    std::lock_guard<std::mutex> lock(memory_mutex);
                    for (auto& pair : tracked_memory) {
                        pair.second.second = true;
                    }
                }

                void finalize(const std::shared_ptr<T>& memory) {
                    std::lock_guard<std::mutex> lock(memory_mutex);
                    tracked_memory[memory].second = true;
                }

                void clear() {
                    std::lock_guard<std::mutex> lock(memory_mutex);
                    tracked_memory.clear();
                }

                ~sycl_garbage_collector() {
                    thread_running = false;
                    garbage_collector_thread.join();
                    for (auto& [memory, event] : tracked_memory) {
                        event.first.wait();
                    }
                    tracked_memory.clear();
                }
            };
        }
    }
}

#endif

#endif