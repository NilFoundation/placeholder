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
#include <map>
#include <mutex>
#include <stack>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

namespace nil::crypto3::bench::detail {
    template<std::integral T>
    inline std::string delimitate_number(T number) {
        std::string str = std::to_string(number);
        for (int i = str.size() - 3; i > 0; i -= 3) {
            str.insert(i, "'");
        }
        return str;
    }

    class ArithmeticCounters {
      public:
        enum Counter { MUL, ADD, SUB, COUNT };

      private:
        static inline std::array<std::atomic_size_t, COUNT> global_counters;

      public:
        static constexpr ArithmeticCounters get_snapshot() {
            if (!std::is_constant_evaluated()) {
                ArithmeticCounters counters;
                for (std::size_t i = 0; i < COUNT; ++i) {
                    counters.counters[i] = global_counters[i];
                }
                return counters;
            } else {
                return {};
            }
        }

        template<Counter c>
        static void register_counter() {
            global_counters[c]++;
        }

        std::string compared_to(const ArithmeticCounters& other) const {
            std::stringstream ss;
            bool first = true;
            for (std::size_t i = 0; i < COUNT; ++i) {
                auto diff = counters[i] - other.counters[i];
                if (diff == 0) {
                    continue;
                }
                if (!first) {
                    ss << ", ";
                }
                switch (i) {
                    case MUL:
                        ss << "mul";
                        break;
                    case ADD:
                        ss << "add";
                        break;
                    case SUB:
                        ss << "sub";
                        break;
                    default:
                        throw std::logic_error("uncovered counter");
                }
                ss << ": " << delimitate_number(diff);
                first = false;
            }
            return ss.str();
        }

      private:
        std::array<std::size_t, COUNT> counters;
    };

    class FFTCounters {
        static constexpr std::size_t FFT_MAX_1 = 30;
        static constexpr std::size_t FFT_TYPE_MAX_1 = 2;

        static inline std::array<std::array<std::atomic_size_t, FFT_MAX_1>,
                                 FFT_TYPE_MAX_1>
            global_ffts;

        template<typename FieldType>
        static constexpr std::size_t get_field_type() {
            return FieldType::modulus_bits * FieldType::arity >= 100;
        }

      public:
        template<typename FieldType>
        static void register_fft(std::size_t log_size) {
            if (log_size >= FFT_MAX_1) {
                throw std::invalid_argument(std::format(
                    "Maximum supported FFT size for profiling is {}", FFT_MAX_1 - 1));
            }
            global_ffts[get_field_type<FieldType>()][log_size]++;
        }

        static FFTCounters get_snapshot() {
            FFTCounters counters;
            for (std::size_t t = 0; t < FFT_TYPE_MAX_1; ++t) {
                for (std::size_t i = 0; i < FFT_MAX_1; ++i) {
                    counters.ffts[t][i] = global_ffts[t][i];
                }
            }
            return counters;
        }

        std::string compared_to(const FFTCounters& other) const {
            std::stringstream ss;
            bool first_type = true;
            for (std::size_t t = 0; t < FFT_TYPE_MAX_1; ++t) {
                bool any = false;
                for (std::size_t i = 0; i < FFT_MAX_1; ++i) {
                    auto diff = ffts[t][i] - other.ffts[t][i];
                    if (diff != 0) {
                        any = true;
                        break;
                    }
                }
                if (!any) {
                    continue;
                }
                if (!first_type) {
                    ss << ", ";
                }
                ss << (t ? "big: " : "small: ");
                bool first = true;
                for (std::size_t i = 0; i < FFT_MAX_1; ++i) {
                    auto diff = ffts[t][i] - other.ffts[t][i];
                    if (diff == 0) {
                        continue;
                    }
                    if (!first) {
                        ss << ", ";
                    }
                    ss << "2^" << i << ": " << diff;
                    first = false;
                }
                first_type = false;
            }
            return ss.str();
        }

      private:
        std::array<std::array<std::size_t, FFT_MAX_1>, FFT_TYPE_MAX_1> ffts;
    };

    // Measures execution time of a given function just once. Prints
    // the time when leaving the function in which this class was created.
    class base_scoped_profiler {
      protected:
        static inline std::size_t global_level = 0;
        static inline std::atomic_bool global_last_open = false;
        static inline std::vector<base_scoped_profiler*> global_stack;
        static inline std::map<std::string, std::chrono::milliseconds>
            global_tag_statistics;

        static void print_prefix() {
            for (std::size_t i = 0; i < global_level; ++i) {
                std::cout << "│  ";
            }
        }

        static void print_prefix_space() {
            for (std::size_t t = 0; t < 2; ++t) {
                print_prefix();
                if (t == 0) {
                    std::cout << std::endl;
                }
            }
        }

        std::string full_name() const { return name + (tag ? " [" + *tag + "]" : ""); }

        void print_start() {
            if (global_last_open) {
                std::cout << std::endl;
            }
            print_prefix_space();
            std::cout << "╭╴" << full_name();
            std::cout.flush();
            ++global_level;
            global_last_open = true;
            global_stack.push_back(this);
        }

        void print_time_result(std::chrono::milliseconds elapsed,
                               bool has_children = false) {
            std::cout << std::format("{}: {} ms", full_name(),
                                     delimitate_number(elapsed.count()));
            if (has_children) {
                auto self_time = elapsed - inner_time;
                auto self_percent =
                    elapsed.count() == 0
                        ? 0
                        : 100 * (self_time.count() * 1.0 / elapsed.count());
                std::cout << std::format(" total, {} ms self, {:.2f}% self",
                                         delimitate_number(self_time.count()),
                                         self_percent);
            }
        }

        std::chrono::milliseconds get_elapsed() const {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - start);
        }

        static void print_tag_statistics(std::chrono::milliseconds elapsed) {
            std::cout << "Tag statistics:" << std::endl;
            for (const auto& [key, value] : global_tag_statistics) {
                auto percent = elapsed.count() == 0
                                   ? 0
                                   : 100 * (value.count() * 1.0 / elapsed.count());
                std::cout << std::format("{}: {} ms, {:.2f}%", key,
                                         delimitate_number(value.count()), percent)
                          << std::endl;
            }
            global_tag_statistics.clear();
        }

        std::chrono::milliseconds print_end() {
            auto elapsed = get_elapsed();
            if (global_last_open) {
                std::cout << '\r';
                --global_level;
                print_prefix();
                std::cout << "• ";
                print_time_result(elapsed);
            } else {
                for (std::size_t t = 0; t < 2; ++t) {
                    print_prefix();
                    if (t == 0) {
                        std::cout << std::endl;
                        --global_level;
                    }
                }
                std::cout << "╰╴";
                print_time_result(elapsed, /*has_children=*/true);
            }
            global_stack.pop_back();
            if (!global_stack.empty()) {
                global_stack.back()->inner_time += elapsed;
            }
            if (tag) {
                global_tag_statistics[*tag] += elapsed;
            }
            global_last_open = false;
            return elapsed;
        }

        base_scoped_profiler(std::string name,
                             std::optional<std::string> tag = std::nullopt)
            : start(std::chrono::high_resolution_clock::now()), name(name), tag(tag) {}

      public:
        static void scoped_log(std::string_view text) {
            if (global_last_open) {
                std::cout << std::endl;
                global_last_open = false;
            }
            print_prefix_space();
            std::cout << "[info] " << text << std::endl;
        }

      protected:
        std::chrono::milliseconds inner_time = std::chrono::milliseconds::zero();
        std::chrono::time_point<std::chrono::high_resolution_clock> start;
        std::string name;
        std::optional<std::string> tag;
    };

    class scoped_profiler : public base_scoped_profiler {
      public:
        scoped_profiler(std::string name, std::optional<std::string> tag = std::nullopt)
            : base_scoped_profiler(name, tag) {
            print_start();
#ifdef NIL_CO3_PROFILE_COUNT_ARITHMETIC_OPS
            arithmetic_counters = ArithmeticCounters::get_snapshot();
#endif
            fft_counters = FFTCounters::get_snapshot();
        }

        void close() {
            auto elapsed = print_end();
#ifdef NIL_CO3_PROFILE_COUNT_ARITHMETIC_OPS
            auto arithmetic_str =
                ArithmeticCounters::get_snapshot().compared_to(arithmetic_counters);
            if (!arithmetic_str.empty()) {
                std::cout << ", arithmetic: " << arithmetic_str;
            }
#endif
            auto ffts_str = FFTCounters::get_snapshot().compared_to(fft_counters);
            if (!ffts_str.empty()) {
                std::cout << ", FFTs: " << ffts_str;
            }
            std::cout << std::endl;
            if (global_stack.empty() && !global_tag_statistics.empty()) {
                std::cout << std::endl;
                print_tag_statistics(elapsed);
            }
            closed = true;
        }

        static void close_last() {
            // NOLINTNEXTLINE
            static_cast<scoped_profiler*>(base_scoped_profiler::global_stack.back())
                ->close();
        }

        ~scoped_profiler() {
            if (!closed) {
                close();
            }
        }

      private:
        bool closed = false;
        ArithmeticCounters arithmetic_counters;
        FFTCounters fft_counters;
    };

    class parallel_scoped_profiler : public base_scoped_profiler {
        static inline std::mutex global_output_lock;

      public:
        parallel_scoped_profiler(std::string name) : base_scoped_profiler(name) {}
        ~parallel_scoped_profiler() {
            auto elapsed = get_elapsed();
            std::scoped_lock lock(global_output_lock);
            if (base_scoped_profiler::global_last_open) {
                std::cout << std::endl;
                base_scoped_profiler::global_last_open = false;
            }
            base_scoped_profiler::print_prefix();
            std::cout << std::endl;
            base_scoped_profiler::print_prefix();
            std::cout << "[parallel] ";
            print_time_result(elapsed);
            std::cout << std::endl;
        }
    };
}  // namespace nil::crypto3::bench::detail

namespace nil::crypto3::bench {
    inline constexpr void register_mul() {
#ifdef NIL_CO3_MP_ENABLE_ARITHMETIC_COUNTERS
        if (!std::is_constant_evaluated()) {
            detail::ArithmeticCounters::register_counter<
                detail::ArithmeticCounters::MUL>();
        }
#endif
    }

    inline constexpr void register_add() {
#ifdef NIL_CO3_MP_ENABLE_ARITHMETIC_COUNTERS
        if (!std::is_constant_evaluated()) {
            detail::ArithmeticCounters::register_counter<
                detail::ArithmeticCounters::ADD>();
        }
#endif
    }

    inline constexpr void register_sub() {
#ifdef NIL_CO3_MP_ENABLE_ARITHMETIC_COUNTERS
        if (!std::is_constant_evaluated()) {
            detail::ArithmeticCounters::register_counter<
                detail::ArithmeticCounters::SUB>();
        }
#endif
    }

    template<typename FieldType>
    void register_fft(std::size_t log_size) {
        detail::FFTCounters::register_fft<FieldType>(log_size);
    }
}  // namespace nil::crypto3::bench

#ifdef PROFILING_ENABLED
#define NIL_CO3_CONCAT_(x, y) x##y
#define NIL_CO3_CONCAT(x, y) NIL_CO3_CONCAT_(x, y)
#define PROFILE_SCOPE(...)                                       \
    nil::crypto3::bench::detail::scoped_profiler NIL_CO3_CONCAT( \
        scoped_profiler_random_name_49a3420b68_, __COUNTER__) {  \
        std::format(__VA_ARGS__)                                 \
    }
#define TAGGED_PROFILE_SCOPE(TAG, ...)                           \
    nil::crypto3::bench::detail::scoped_profiler NIL_CO3_CONCAT( \
        scoped_profiler_random_name_49a3420b68_, __COUNTER__) {  \
        std::format(__VA_ARGS__), TAG                            \
    }
#define PROFILE_SCOPE_END() nil::crypto3::bench::detail::scoped_profiler::close_last()
#define PARALLEL_PROFILE_SCOPE(...)                                       \
    nil::crypto3::bench::detail::parallel_scoped_profiler NIL_CO3_CONCAT( \
        scoped_profiler_random_name_49a3420b68_, __COUNTER__) {           \
        std::format(__VA_ARGS__)                                          \
    }
#define SCOPED_LOG(...)                                                \
    do {                                                               \
        nil::crypto3::bench::detail::base_scoped_profiler::scoped_log( \
            std::format(__VA_ARGS__));                                 \
    } while (false)
#else
#include <boost/log/trivial.hpp>
#define PROFILE_SCOPE(...)
#define TAGGED_PROFILE_SCOPE(TAG, ...)
#define PROFILE_SCOPE_END()
#define PARALLEL_PROFILE_SCOPE(...)
#define SCOPED_LOG(...)                                      \
    do {                                                     \
        BOOST_LOG_TRIVIAL(info) << std::format(__VA_ARGS__); \
    } while (false)
#endif

#endif  // CRYPTO3_SCOPED_PROFILER_HPP
