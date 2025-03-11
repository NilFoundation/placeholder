//---------------------------------------------------------------------------//
// Copyright (c) 2023 Martun Karapetyan <martun@nil.foundation>
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
// Copyright (c) 2025 Andrey Nefedov <ioxid@nil.foundation>
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

#ifndef CRYPTO3_SCOPED_PROFILER_HPP
#define CRYPTO3_SCOPED_PROFILER_HPP

#include <atomic>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <stack>
#include <string>
#include <type_traits>
#include <unordered_map>

#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops/common.hpp"

namespace nil::crypto3::bench::detail {
    inline void no_scope_profiling(const std::string& name, bool stop = false) {
        static std::stack<std::pair<
            std::string, std::chrono::time_point<std::chrono::high_resolution_clock>>>
            points;
        if (stop) {
            const auto curr = std::chrono::high_resolution_clock::now();
            auto start = curr;
            if ((points.size() > 0) && (points.top().first == name)) {
                start = points.top().second;
                points.pop();
            }
            auto elapsed =
                std::chrono::duration_cast<std::chrono::milliseconds>(curr - start);
            std::cout << name << ": " << std::fixed << std::setprecision(3)
                      << elapsed.count() << " ms" << std::endl;
        } else {
            const auto start = std::chrono::high_resolution_clock::now();
            const auto point = std::make_pair<>(name, start);
            points.push(point);
        }
    }

    template<std::integral T>
    std::string delimitate_number(T number) {
        std::string str = std::to_string(number);
        for (int i = str.size() - 3; i > 0; i -= 3) {
            str.insert(i, "'");
        }
        return str;
    }

    // NOLINTNEXTLINE
    inline std::size_t global_level = 0;
    // NOLINTNEXTLINE
    inline std::atomic_bool global_last_open = false;

    inline void print_prefix() {
        for (std::size_t i = 0; i < global_level; ++i) {
            std::cout << "│  ";
        }
    }

    // Measures execution time of a given function just once. Prints
    // the time when leaving the function in which this class was created.
    class base_scoped_profiler {
      protected:
        void print_start() {
            if (global_last_open) {
                std::cout << std::endl;
            }
            for (std::size_t t = 0; t < 2; ++t) {
                print_prefix();
                if (t == 0) {
                    std::cout << std::endl;
                }
            }
            std::cout << "╭╴" << name;
            std::cout.flush();
            ++global_level;
            global_last_open = true;
        }

        void print_time_result(std::chrono::milliseconds elapsed) {
            std::cout << name << ": " << delimitate_number(elapsed.count()) << " ms";
        }

        std::chrono::milliseconds get_elapsed() {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - start);
        }

        void print_end() {
            auto elapsed = get_elapsed();
            if (global_last_open) {
                std::cout << '\r';
                --global_level;
                print_prefix();
                std::cout << "• ";
                print_time_result(elapsed);
                global_last_open = false;
                return;
            }
            for (std::size_t t = 0; t < 2; ++t) {
                print_prefix();
                if (t == 0) {
                    std::cout << std::endl;
                    --global_level;
                }
            }
            std::cout << "╰╴";
            print_time_result(elapsed);
            global_last_open = false;
        }

        base_scoped_profiler(std::string name)
            : start(std::chrono::high_resolution_clock::now()), name(name) {}

        std::chrono::time_point<std::chrono::high_resolution_clock> start;
        std::string name;
    };

    class scoped_profiler : public base_scoped_profiler {
        nil::crypto3::multiprecision::detail::counters counters;

      public:
        scoped_profiler(std::string name) : base_scoped_profiler(name) {
            print_start();
#ifdef NIL_CO3_PROFILE_COUNT_ARITHMETIC_OPS
            counters = nil::crypto3::multiprecision::detail::get_counters();
#endif
        }
        ~scoped_profiler() {
            print_end();
            auto new_counters = nil::crypto3::multiprecision::detail::get_counters();
#ifdef NIL_CO3_PROFILE_COUNT_ARITHMETIC_OPS
            std::cout
                << ", mul: "
                << delimitate_number(new_counters.mul_counter - counters.mul_counter)
                << ", add: "
                << delimitate_number(new_counters.add_counter - counters.add_counter)
                << ", sub: "
                << delimitate_number(new_counters.sub_counter - counters.sub_counter);
#endif
            std::cout << std::endl;
        }
    };

    class parallel_scoped_profiler : public base_scoped_profiler {
        static std::mutex output_lock;

      public:
        parallel_scoped_profiler(std::string name) : base_scoped_profiler(name) {}
        ~parallel_scoped_profiler() {
            auto elapsed = get_elapsed();
            std::scoped_lock lock(output_lock);
            if (detail::global_last_open) {
                std::cout << std::endl;
                detail::global_last_open = false;
            }
            print_prefix();
            std::cout << std::endl;
            print_prefix();
            std::cout << "[parallel] ";
            print_time_result(elapsed);
            std::cout << std::endl;
        }
    };

    class call_stats {
      public:
        // Make this class singleton.
        static call_stats& get_stats() {
            static call_stats instance;
            return instance;
        }

        void add_stat(const std::string& name, uint64_t time_ms) {
            call_counts[name]++;
            call_miliseconds[name] += time_ms;
        }

      private:
        call_stats() {}
        ~call_stats() {
            for (const auto& [name, count] : call_counts) {
                uint64_t miliseconds = call_miliseconds[name] / 1000000;
                std::cout << name << ": " << count << " calls " << miliseconds / 1000
                          << " sec " << miliseconds % 1000 << " ms" << std::endl;
            }
        }

        std::unordered_map<std::string, uint64_t> call_counts;
        std::unordered_map<std::string, uint64_t> call_miliseconds;
    };

    // Measures the total execution time of the functions it's placed in, and
    // the number of calls. Prints the time and number of calls on program
    // exit.
    class scoped_aggregate_profiler {
      public:
        scoped_aggregate_profiler(std::string name)
            : start(std::chrono::high_resolution_clock::now()), name(name) {}

        ~scoped_aggregate_profiler() {
            auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::high_resolution_clock::now() - start);
            call_stats::get_stats().add_stat(name, elapsed.count());
        }

      private:
        std::chrono::time_point<std::chrono::high_resolution_clock> start;
        std::string name;
    };
}  // namespace nil::crypto3::bench::detail

#ifdef PROFILING_ENABLED
#define NIL_CO3_CONCAT_(x, y) x##y
#define NIL_CO3_CONCAT(x, y) NIL_CO3_CONCAT_(x, y)
#define PROFILE_SCOPE(name)                                      \
    nil::crypto3::bench::detail::scoped_profiler NIL_CO3_CONCAT( \
        scoped_profiler_random_name_49a3420b68_, __COUNTER__){name};
#define PARALLEL_PROFILE_SCOPE(name)                                      \
    nil::crypto3::bench::detail::parallel_scoped_profiler NIL_CO3_CONCAT( \
        scoped_profiler_random_name_49a3420b68_, __COUNTER__){name};
#else
#define PROFILE_SCOPE(name)
#define PARALLEL_PROFILE_SCOPE(name)
#endif

namespace nil::crypto3::bench {
    inline void scoped_log(const std::string& text) {
        if (detail::global_last_open) {
            std::cout << std::endl;
            detail::global_last_open = false;
        }
        for (std::size_t t = 0; t < 2; ++t) {
            detail::print_prefix();
            if (t == 0) {
                std::cout << std::endl;
            }
        }
        std::cout << "[info] " << text << std::endl;
    }
}  // namespace nil::crypto3::bench

#ifdef TIME_LOG_ENABLED
#define TIME_LOG_SCOPE(name) nil::crypto3::bench::detail::scoped_profiler profiler(name);
#define TIME_LOG_START(name) nil::crypto3::bench::detail::no_scope_profiling(name, false);
#define TIME_LOG_END(name) nil::crypto3::bench::detail::no_scope_profiling(name, true);
#else
#define TIME_LOG_SCOPE(name)
#define TIME_LOG_START(name)
#define TIME_LOG_END(name)
#endif

#endif  // CRYPTO3_SCOPED_PROFILER_HPP
