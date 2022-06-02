//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
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

#ifndef ACTOR_MATH_POLYNOMIAL_BASIC_OPERATIONS_HPP
#define ACTOR_MATH_POLYNOMIAL_BASIC_OPERATIONS_HPP

#include <algorithm>
#include <vector>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/actor/math/domains/detail/basic_radix2_domain_aux.hpp>
#include <nil/crypto3/math/detail/field_utils.hpp>

namespace nil {
    namespace actor {
        namespace math {
            /**
             * Returns true if polynomial A is a zero polynomial.
             */
            template<typename Range>
            bool is_zero(const Range &a) {
                return std::all_of(
                    std::begin(a),
                    std::end(a),
                    [](typename std::iterator_traits<decltype(std::begin(std::declval<Range>()))>::value_type i) {
                        return i ==
                               typename std::iterator_traits<decltype(std::begin(std::declval<Range>()))>::value_type();
                    });
            }

            template<typename Range>
            void reverse(Range &a, std::size_t n) {
                std::reverse(std::begin(a), std::end(a));
                a.resize(n);
            }

            /**
             * Removes extraneous zero entries from in vector representation of polynomial.
             * Example - Degree-4 Polynomial: [0, 1, 2, 3, 4, 0, 0, 0, 0] -> [0, 1, 2, 3, 4]
             * Note: Simplest condensed form is a zero polynomial of vector form: [0]
             */
            template<typename Range>
            void condense(Range &a) {
                std::size_t i = std::distance(std::cbegin(a), std::cend(a));
                while (i > 1 &&
                       a[i - 1] ==
                           typename std::iterator_traits<decltype(std::begin(std::declval<Range>()))>::value_type()) {
                    --i;
                }
                a.resize(i);
            }

            /**
             * Computes the standard polynomial addition, polynomial A + polynomial B, and stores result in
             * polynomial C.
             */
            template<typename Range>
            future<> addition(Range &c, const Range &a, const Range &b) {

                typedef
                    typename std::iterator_traits<decltype(std::begin(std::declval<Range>()))>::value_type value_type;

                if (is_zero(a)) {
                    c = b;
                } else if (is_zero(b)) {
                    c = a;
                } else {
                    std::size_t a_size = std::distance(std::begin(a), std::end(a));
                    std::size_t b_size = std::distance(std::begin(b), std::end(b));
                    std::size_t min_size = std::min(a_size, b_size);

                    if (a_size > b_size) {
                        c.resize(a_size);
                        std::copy(std::begin(a) + b_size, std::end(a), std::begin(c) + b_size);
                    } else {
                        c.resize(b_size);
                        std::copy(std::begin(b) + a_size, std::end(b), std::begin(c) + a_size);
                    }

                    std::vector<future<>> fut;
                    size_t cpu_usage = std::min(min_size, (std::size_t)smp::count);
                    size_t element_per_cpu = min_size / smp::count;

                    for (auto i = 0; i < cpu_usage; ++i) {
                        auto begin = element_per_cpu * i;
                        auto end = (i == cpu_usage - 1) ? min_size : element_per_cpu * (i + 1);
                        fut.emplace_back(smp::submit_to(i, [begin, end, &c, &a, &b]() {
                            for (std::size_t i = begin; i < end; i++) {
                                c[i] = a[i] + b[i];
                            }
                            return nil::actor::make_ready_future<>();
                        }));
                    }

                    when_all(fut.begin(), fut.end()).get();

                }

                condense(c);
                return make_ready_future<>();
            }

            /**
             * Computes the standard polynomial subtraction, polynomial A - polynomial B, and stores result in
             * polynomial C.
             */
            template<typename Range>
            future<> subtraction(Range &c, const Range &a, const Range &b) {

                typedef
                    typename std::iterator_traits<decltype(std::begin(std::declval<Range>()))>::value_type value_type;

                if (is_zero(b)) {
                    c = a;
                } else if (is_zero(a)) {
                    c.resize(b.size());
                    std::transform(b.begin(), b.end(), c.begin(), std::negate<value_type>());
                } else {
                    std::size_t a_size = a.size();
                    std::size_t b_size = b.size();
                    std::size_t min_size = std::min(a_size, b_size);

                    if (a_size > b_size) {
                        c.resize(a_size);
                        std::copy(a.begin() + b_size, a.end(), c.begin() + b_size);
                    } else {
                        c.resize(b_size);
                        std::transform(b.begin() + a_size, b.end(), c.begin() + a_size, std::negate<value_type>());
                    }

                    std::vector<future<>> fut;
                    size_t cpu_usage = std::min(min_size, (std::size_t)smp::count);
                    size_t element_per_cpu = min_size / smp::count;

                    for (auto i = 0; i < cpu_usage; ++i) {
                        auto begin = element_per_cpu * i;
                        auto end = (i == cpu_usage - 1) ? min_size : element_per_cpu * (i + 1);
                        fut.emplace_back(smp::submit_to(i, [begin, end, &c, &a, &b]() {
                            for (std::size_t i = begin; i < end; i++) {
                                c[i] = a[i] - b[i];
                            }
                            return nil::actor::make_ready_future<>();
                        }));
                    }

                    when_all(fut.begin(), fut.end()).get();
                }

                condense(c);
                return make_ready_future<>();
            }

            /**
             * Perform the multiplication of two polynomials, polynomial A * polynomial B, using FFT, and stores
             * result in polynomial C.
             */
            template<typename Range>
            future<> multiplication(Range &c, const Range &a, const Range &b) {

                typedef
                    typename std::iterator_traits<decltype(std::begin(std::declval<Range>()))>::value_type value_type;

                typedef typename value_type::field_type FieldType;
                BOOST_STATIC_ASSERT(crypto3::algebra::is_field<FieldType>::value);
                BOOST_STATIC_ASSERT(std::is_same<typename FieldType::value_type, value_type>::value);

                const std::size_t n = crypto3::math::detail::power_of_two(a.size() + b.size() - 1);
                value_type omega = crypto3::math::unity_root<FieldType>(n);

                Range u(a), v(b);
                u.resize(n, value_type::zero());
                v.resize(n, value_type::zero());
                c.resize(n, value_type::zero());

                detail::basic_radix2_fft<FieldType>(u, omega).get();
                detail::basic_radix2_fft<FieldType>(v, omega).get();

                std::vector<future<>> fut;
                size_t cpu_usage = std::min(n, (std::size_t)smp::count);
                size_t element_per_cpu = n / smp::count;

                for (auto i = 0; i < cpu_usage; ++i) {
                    auto begin = element_per_cpu * i;
                    auto end = (i == cpu_usage - 1) ? n : element_per_cpu * (i + 1);
                    fut.emplace_back(smp::submit_to(i, [begin, end, &c, &u, &v]() {
                        for (std::size_t i = begin; i < end; i++) {
                            c[i] = u[i] * v[i];
                        }
                        return nil::actor::make_ready_future<>();
                    }));
                }

                when_all(fut.begin(), fut.end()).get();

                detail::basic_radix2_fft<FieldType>(c, omega.inversed()).get();

                const value_type sconst = value_type(n).inversed();

                fut.clear();

                for (auto i = 0; i < cpu_usage; ++i) {
                    auto begin = element_per_cpu * i;
                    auto end = (i == cpu_usage - 1) ? n : element_per_cpu * (i + 1);
                    fut.emplace_back(smp::submit_to(i, [begin, end, &c, sconst]() {
                        for (std::size_t i = begin; i < end; i++) {
                            c[i] *= sconst;
                        }
                        return nil::actor::make_ready_future<>();
                    }));
                }

                when_all(fut.begin(), fut.end()).get();

                condense(c);

                return make_ready_future<>();
            }

            /**
             * Compute the transposed, polynomial multiplication of vector a and vector b.
             * Below we make use of the transposed multiplication definition from
             * [Bostan, Lecerf, & Schost, 2003. Tellegen's Principle in Practice, on page 39].
             */
            template<typename Range>
            Range transpose_multiplication(const std::size_t &n, const Range &a, const Range &c) {

                typedef
                    typename std::iterator_traits<decltype(std::begin(std::declval<Range>()))>::value_type value_type;

                const std::size_t m = a.size();
                // if (c.size() - 1 > m + n)
                // throw InvalidSizeException("expected c.size() - 1 <= m + n");

                Range r(a);
                reverse(r, m);
                multiplication(r, r, c);

                /* Determine Middle Product */
                Range result;
                for (std::size_t i = m - 1; i < n + m; i++) {
                    result.emplace_back(r[i]);
                }
                return result;
            }

            /**
             * Perform the standard Euclidean Division algorithm.
             * Input: Polynomial A, Polynomial B, where A / B
             * Output: Polynomial Q, Polynomial R, such that A = (Q * B) + R.
             */
            template<typename Range>
            void division(Range &q, Range &r, const Range &a, const Range &b) {

                typedef
                    typename std::iterator_traits<decltype(std::begin(std::declval<Range>()))>::value_type value_type;

                std::size_t d = b.size() - 1;       /* Degree of B */
                value_type c = b.back().inversed(); /* Inverse of Leading Coefficient of B */

                r = Range(a);
                q = Range(r.size(), value_type::zero());

                std::size_t r_deg = r.size() - 1;
                std::size_t shift;

                while (r_deg >= d && !is_zero(r)) {
                    if (r_deg >= d)
                        shift = r_deg - d;
                    else
                        shift = 0;

                    value_type lead_coeff = r.back() * c;

                    q[shift] += lead_coeff;

                    if (b.size() + shift + 1 > r.size())
                        r.resize(b.size() + shift + 1);
                    auto glambda = [=](value_type x, value_type y) { return y - (x * lead_coeff); };
                    std::transform(b.begin(), b.end(), r.begin() + shift, r.begin() + shift, glambda);
                    condense(r);

                    r_deg = r.size() - 1;
                }
                condense(q);
            }
        }    // namespace math
    }        // namespace actor
}    // namespace nil

#endif    // ACTOR_MATH_POLYNOMIAL_BASIC_OPERATIONS_HPP
