//---------------------------------------------------------------------------//
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
// Copyright (c) 2025 Andrey Nefedov <ioxid@nil.foundation>
//
// SPDX-License-Identifier: MIT
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

#ifndef CRYPTO3_BENCHMARK_HPP
#define CRYPTO3_BENCHMARK_HPP

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <concepts>
#include <cstddef>
#include <format>
#include <functional>
#include <iostream>
#include <ratio>
#include <string>
#include <tuple>
#include <type_traits>
#include <vector>

#include <nil/crypto3/algebra/random_element.hpp>

#define NIL_CO3_USE_IF_NOT_VOID(expr)                                    \
    if constexpr (!std::is_void_v<decltype(expr)>) {                     \
        /* volatile hints to compiler that it has important side effects \
         * and call should not be optimized out */                       \
        [[maybe_unused]] volatile auto r = (expr);                       \
    } else {                                                             \
        (expr);                                                          \
    }

namespace nil::crypto3::bench {
    namespace detail {
        template<std::size_t ABSTRACT_ITERATIONS = 1, std::invocable<std::size_t> P,
                 typename F>
        void run_benchmark_impl(std::string const& name, const P& prepare,
                                const F& func) {
            using duration = std::chrono::duration<double, std::nano>;

            constexpr std::size_t WARMUP_BATCH_SIZE = 10;
            constexpr duration WARMUP_DURATION = std::chrono::milliseconds(500);
            constexpr std::size_t MEASUREMENTS = 100;

            auto run_batch = [&func](std::size_t batch_size, auto& args) {
                NIL_CO3_USE_IF_NOT_VOID(std::apply(
                    [&func, batch_size](auto&... args) {
                        return std::invoke(func, batch_size, args...);
                    },
                    args));
            };

            auto run_at_least = [&](duration const& dur) {
                std::size_t total_runs = 0;
                auto start = std::chrono::high_resolution_clock::now();
                while (std::chrono::high_resolution_clock::now() - start < dur) {
                    auto args = prepare(WARMUP_BATCH_SIZE);
                    run_batch(WARMUP_BATCH_SIZE, args);
                    [[maybe_unused]] volatile auto r = args;
                    total_runs += WARMUP_BATCH_SIZE;
                }
                return total_runs;
            };

            const std::size_t BATCH_SIZE =
                1 + run_at_least(WARMUP_DURATION) / MEASUREMENTS / 10;

            std::vector<double> durations(MEASUREMENTS);
            for (std::size_t m = 0; m < MEASUREMENTS; ++m) {
                auto args = prepare(BATCH_SIZE);
                auto start = std::chrono::high_resolution_clock::now();
                run_batch(BATCH_SIZE, args);
                auto finish = std::chrono::high_resolution_clock::now();
                durations[m] = static_cast<double>((finish - start).count()) /
                               static_cast<double>(BATCH_SIZE) /
                               static_cast<double>(ABSTRACT_ITERATIONS);
                [[maybe_unused]] volatile auto r = args;
            }

            std::sort(durations.begin(), durations.end());

            // discard top 20% outliers
            durations.resize(
                static_cast<std::size_t>(static_cast<double>(MEASUREMENTS) * 0.8));

            double median = durations[durations.size() / 2];
            double mean = 0, stddiv = 0;

            for (auto& dur : durations) {
                mean += dur;
                stddiv += dur * dur;
            }

            mean /= static_cast<double>(durations.size());
            // stddiv^2 = E x^2 - (E x)^2
            stddiv = sqrt(stddiv / static_cast<double>(durations.size()) - mean * mean);

            // https://support.numxl.com/hc/en-us/articles/115001223503-MdAPE-Median-Absolute-Percentage-Error
            for (auto& dur : durations) {
                dur = (dur - median) / dur;
                if (dur < 0) {
                    dur = -dur;
                }
            }
            std::sort(durations.begin(), durations.end());
            double MdAPE = durations[durations.size() / 2];

            std::size_t multiplier = 1;
            std::string unit;

            while (mean >= 10e3) {
                ++multiplier;
                mean /= 1e3;
                median /= 1e3;
                stddiv /= 1e3;
            }

            switch (multiplier) {
                case 1:
                    unit = "ns";
                    break;
                case 2:
                    unit = "µs";
                    break;
                case 3:
                    unit = "ms";
                    break;
                case 4:
                    unit = "s";
                    break;
                default:
                    unit = "??";
            }

            std::cout << std::format(
                             "{} mean: {:9.3f}{} stddiv: {:5.2f} median: {:9.3f}{} err: "
                             "{:.2f}%",
                             name, mean, unit, stddiv, median, unit, MdAPE * 100)
                      << std::endl;
        }

        template<typename T>
        std::vector<typename T::value_type> generate_random_data(std::size_t size) {
            std::vector<typename T::value_type> data;
            for (std::size_t i = 0; i < size; ++i) {
                data.push_back(algebra::random_element<T>());
            }
            return data;
        }
    }  // namespace detail

    template<typename T, typename F>
    void run_fold_benchmark(std::string const& name, const F& func) {
        using V = typename T::value_type;
        detail::run_benchmark_impl(
            name,
            [](std::size_t batch_size) {
                std::vector<V> vals;
                for (std::size_t b = 0; b < batch_size; ++b) {
                    vals.push_back(algebra::random_element<T>());
                }
                return std::make_tuple(algebra::random_element<T>(), vals);
            },
            [&func](std::size_t batch_size, V& accum, const std::vector<V>& vals) {
                for (std::size_t b = 0; b < batch_size; ++b) {
                    std::invoke(func, accum, vals[b]);
                }
                return accum;
            });
    }

    template<std::size_t folds_count, typename T, typename F>
    void run_independent_folds_benchmark(std::string const& name, const F& func) {
        using V = T::value_type;
        detail::run_benchmark_impl<folds_count>(
            name,
            [](std::size_t batch_size) {
                std::array<V, folds_count> accums;
                for (std::size_t i = 0; i < folds_count; ++i) {
                    accums[i] = algebra::random_element<T>();
                };
                std::vector<V> vals;
                for (std::size_t b = 0; b < batch_size; ++b) {
                    vals.push_back(algebra::random_element<T>());
                }
                return make_tuple(accums, vals);
            },
            [&func](std::size_t batch_size, std::array<V, folds_count> accums,
                    const std::vector<V>& vals) {
                for (std::size_t b = 0; b < batch_size; ++b) {
                    for (std::size_t i = 0; i < folds_count; ++i) {
                        std::invoke(func, accums[i], vals[b]);
                    }
                }
                return accums;
            });
    }

    template<typename... Args, typename F>
    void run_benchmark(std::string const& name, const F& func) {
        detail::run_benchmark_impl(
            name,
            [](std::size_t batch_size) {
                return std::make_tuple(detail::generate_random_data<Args>(batch_size)...);
            },
            [&func](std::size_t batch_size, auto&... vals) {
                for (std::size_t b = 0; b < batch_size; ++b) {
                    NIL_CO3_USE_IF_NOT_VOID(std::invoke(func, (vals[b])...));
                }
            });
    }
}  // namespace nil::crypto3::bench

#undef NIL_CO3_USE_IF_NOT_VOID

#endif /* CRYPTO3_BENCHMARK_HPP */
