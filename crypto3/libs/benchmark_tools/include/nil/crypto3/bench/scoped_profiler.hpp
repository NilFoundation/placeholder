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
#include <format>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <stack>
#include <string>
#include <type_traits>
#include <unordered_map>

namespace nil::crypto3::bench::detail {
    // NOLINTNEXTLINE
    inline std::atomic_size_t mul_counter;
    // NOLINTNEXTLINE
    inline std::atomic_size_t add_counter;
    // NOLINTNEXTLINE
    inline std::atomic_size_t sub_counter;

    struct ArithmeticCounters {
        std::size_t mul_counter;
        std::size_t add_counter;
        std::size_t sub_counter;

        std::string compared_to(const ArithmeticCounters& other) const {
            std::stringstream ss;
            auto diff = mul_counter - other.mul_counter;
            if (diff != 0) {
                ss << "mul: " << diff << ", ";
            }
            diff = add_counter - other.add_counter;
            if (diff != 0) {
                ss << "add: " << diff << ", ";
            }
            diff = sub_counter - other.sub_counter;
            if (diff != 0) {
                ss << "sub: " << diff << ", ";
            }
            return ss.str();
        }
    };

    inline constexpr ArithmeticCounters get_arithmetic_counters() {
        if (!std::is_constant_evaluated()) {
            return {mul_counter, add_counter, sub_counter};
        } else {
            return {};
        }
    }

    constexpr std::size_t FFT_MAX_1 = 30;

    struct FFTCounters {
        std::array<std::size_t, FFT_MAX_1> ffts;

        std::string compared_to(const FFTCounters& other) const {
            std::stringstream ss;
            bool first = true;
            for (std::size_t i = 0; i < FFT_MAX_1; ++i) {
                auto diff = ffts[i] - other.ffts[i];
                if (diff != 0) {
                    if (!first) {
                        ss << ", ";
                    }
                    ss << "2^" << i << ": " << diff;
                    first = false;
                }
            }
            return ss.str();
        }
    };

    // NOLINTNEXTLINE
    inline std::array<std::atomic_size_t, FFT_MAX_1> ffts;

    inline FFTCounters get_fft_counters() {
        FFTCounters counters;
        for (std::size_t i = 0; i < FFT_MAX_1; ++i) {
            counters.ffts[i] = ffts[i];
        }
        return counters;
    }

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
        inline static std::vector<std::chrono::milliseconds> inner_times;

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
            inner_times.emplace_back();
        }

        void print_time_result(std::chrono::milliseconds elapsed,
                               bool has_children = false) {
            std::cout << std::format("{}: {} ms", name,
                                     delimitate_number(elapsed.count()));
            if (has_children) {
                auto self_time = elapsed - inner_times.back();
                auto self_percent =
                    self_time.count() == 0
                        ? 0
                        : 100 * (self_time.count() * 1.0 / elapsed.count());
                std::cout << std::format(" total, {} ms self, {:.2f}% self",
                                         delimitate_number(self_time.count()),
                                         self_percent);
            }
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
                inner_times.pop_back();
                if (!inner_times.empty()) {
                    inner_times.back() += elapsed;
                }
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
            print_time_result(elapsed, /*has_children=*/true);
            inner_times.pop_back();
            if (!inner_times.empty()) {
                inner_times.back() += elapsed;
            }
            global_last_open = false;
        }

        base_scoped_profiler(std::string name)
            : start(std::chrono::high_resolution_clock::now()), name(name) {}

        std::chrono::time_point<std::chrono::high_resolution_clock> start;
        std::string name;
    };

    class scoped_profiler : public base_scoped_profiler {
        ArithmeticCounters arithmetic_counters;
        FFTCounters fft_counters;

      public:
        scoped_profiler(std::string name) : base_scoped_profiler(name) {
            print_start();
#ifdef NIL_CO3_PROFILE_COUNT_ARITHMETIC_OPS
            counters = nil::crypto3::multiprecision::detail::get_counters();
#endif
            fft_counters = get_fft_counters();
        }
        ~scoped_profiler() {
            print_end();
#ifdef NIL_CO3_PROFILE_COUNT_ARITHMETIC_OPS
            std::cout << ", arithmetic: "
                      << get_arithmetic_counters().compared_to(arithmetic_counters);
#endif
            auto ffts_str = get_fft_counters().compared_to(fft_counters);
            if (!ffts_str.empty()) {
                std::cout << ", FFTs: " << ffts_str;
            }
            std::cout << std::endl;
        }
    };

    class parallel_scoped_profiler : public base_scoped_profiler {
        inline static std::mutex output_lock;

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
}  // namespace nil::crypto3::bench::detail

namespace nil::crypto3::bench {
    inline constexpr void register_mul() {
        if (!std::is_constant_evaluated()) {
#ifdef NIL_CO3_MP_ENABLE_ARITHMETIC_COUNTERS
            mul_counter++;
#endif
        }
    }

    inline constexpr void register_add() {
        if (!std::is_constant_evaluated()) {
#ifdef NIL_CO3_MP_ENABLE_ARITHMETIC_COUNTERS
            add_counter++;
#endif
        }
    }

    inline constexpr void register_sub() {
        if (!std::is_constant_evaluated()) {
#ifdef NIL_CO3_MP_ENABLE_ARITHMETIC_COUNTERS
            sub_counter++;
#endif
        }
    }

    inline void register_fft(std::size_t log_size) { detail::ffts[log_size]++; }
}  // namespace nil::crypto3::bench

#ifdef PROFILING_ENABLED
#define NIL_CO3_CONCAT_(x, y) x##y
#define NIL_CO3_CONCAT(x, y) NIL_CO3_CONCAT_(x, y)
#define PROFILE_SCOPE(...)                                       \
    nil::crypto3::bench::detail::scoped_profiler NIL_CO3_CONCAT( \
        scoped_profiler_random_name_49a3420b68_, __COUNTER__) {  \
        std::format(__VA_ARGS__)                                 \
    }
#define PARALLEL_PROFILE_SCOPE(...)                                       \
    nil::crypto3::bench::detail::parallel_scoped_profiler NIL_CO3_CONCAT( \
        scoped_profiler_random_name_49a3420b68_, __COUNTER__) {           \
        std::format(__VA_ARGS__)                                          \
    }
#define SCOPED_LOG(...) nil::crypto3::bench::detail::scoped_log(std::format(__VA_ARGS__))
#else
#define PROFILE_SCOPE(...)
#define PARALLEL_PROFILE_SCOPE(...)
#define SCOPED_LOG(...) BOOST_LOG_TRIVIAL(info) << std::format(__VA_ARGS__)
#endif

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
