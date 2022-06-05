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

#ifndef ACTOR_MATH_BASIC_RADIX2_DOMAIN_AUX_HPP
#define ACTOR_MATH_BASIC_RADIX2_DOMAIN_AUX_HPP

#include <algorithm>
#include <vector>

#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/actor/core/smp.hh>
#include <nil/actor/core/when_all.hh>
#include <nil/actor/core/future.hh>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/detail/field_utils.hpp>

#include <nil/crypto3/math/domains/detail/basic_radix2_domain_aux.hpp>

namespace nil {
    namespace actor {
        namespace math {
            namespace detail {

                template<typename FieldType, typename Range>
                future<> basic_radix2_fft(Range &a, const typename FieldType::value_type &omega) {

                    std::size_t num_cpus = nil::actor::smp::count;

                    const std::size_t log_cpus = (num_cpus & (num_cpus - 1)) == 0 ? log2(num_cpus) : log2(num_cpus) - 1;

                    typedef typename std::iterator_traits<decltype(std::begin(std::declval<Range>()))>::value_type
                        value_type;

                    BOOST_STATIC_ASSERT(crypto3::algebra::is_field<FieldType>::value);
                    BOOST_STATIC_ASSERT(std::is_same<typename FieldType::value_type, value_type>::value);

                    num_cpus = 1ul << log_cpus;

                    const std::size_t m = a.size();
                    const std::size_t log_m = log2(m);

                    BOOST_ASSERT_MSG(m == 1ul << log_m, "Expected m == 1ul<<log_m");

                    if (log_m < log_cpus || log_cpus == 0) {
                        crypto3::math::detail::basic_radix2_fft<FieldType>(a, omega);
                        return make_ready_future<>();
                    }

                    std::vector<std::vector<value_type>> tmp(
                        num_cpus, std::vector<value_type>(1ul << (log_m - log_cpus), value_type::zero()));

                    std::vector<future<>> fut;

                    const value_type omega_num_cpus = omega.pow(num_cpus);

                    for (std::size_t j = 0; j < num_cpus; ++j) {
                        const value_type omega_j = omega.pow(j);
                        const value_type omega_step = omega.pow(j << (log_m - log_cpus));

                        fut.emplace_back(smp::submit_to(
                            j, [j, omega_num_cpus, omega_j, omega_step, log_m, log_cpus, num_cpus, &tmp, &a]() {
                                value_type elt = value_type::one();
                                for (std::size_t i = 0; i < 1ul << (log_m - log_cpus); ++i) {
                                    for (std::size_t s = 0; s < num_cpus; ++s) {
                                        // invariant: elt is omega^(j*idx)
                                        const std::size_t idx = (i + (s << (log_m - log_cpus))) % (1u << log_m);
                                        tmp[j][i] += a[idx] * elt;
                                        elt *= omega_step;
                                    }
                                    elt *= omega_j;
                                }

                                crypto3::math::detail::basic_radix2_fft<FieldType>(tmp[j], omega_num_cpus);

                                return nil::actor::make_ready_future<>();
                            }));
                    }
                    when_all(fut.begin(), fut.end()).get();

                    fut.clear();

                    for (std::size_t i = 0; i < num_cpus; ++i) {
                        fut.emplace_back(smp::submit_to(i, [i, log_m, log_cpus, &tmp, &a]() {
                            for (std::size_t j = 0; j < 1ul << (log_m - log_cpus); ++j) {
                                // now: i = idx >> (log_m - log_cpus) and j = idx % (1u << (log_m - log_cpus)), for idx
                                // =
                                // ((i<<(log_m-log_cpus))+j) % (1u << log_m)
                                a[(j << log_cpus) + i] = tmp[i][j];
                            }
                            return nil::actor::make_ready_future<>();
                        }));
                    }
                    when_all(fut.begin(), fut.end()).get();
                    return make_ready_future<>();
                }

                /**
                 * Compute the m Lagrange coefficients, relative to the set S={omega^{0},...,omega^{m-1}}, at the
                 * field element t.
                 */
                template<typename FieldType>
                std::vector<typename FieldType::value_type>
                    basic_radix2_evaluate_all_lagrange_polynomials(const std::size_t m,
                                                                   const typename FieldType::value_type &t) {
                    typedef typename FieldType::value_type value_type;

                    if (m == 1) {
                        return std::vector<value_type>(1, value_type::one());
                    }

                    BOOST_ASSERT_MSG(m == (1u << static_cast<std::size_t>(std::ceil(std::log2(m)))),
                                     "Expected m == (1u << log2(m))");

                    const value_type omega = crypto3::math::unity_root<FieldType>(m);

                    std::vector<value_type> u(m, value_type::zero());

                    /*
                     If t equals one of the roots of unity in S={omega^{0},...,omega^{m-1}}
                     then output 1 at the right place, and 0 elsewhere
                     */

                    if (t.pow(m) == value_type::one()) {
                        value_type omega_i = value_type::one();
                        for (std::size_t i = 0; i < m; ++i) {
                            if (omega_i == t)    // i.e., t equals omega^i
                            {
                                u[i] = value_type::one();
                                return u;
                            }

                            omega_i *= omega;
                        }
                    }

                    /*
                     Otherwise, if t does not equal any of the roots of unity in S,
                     then compute each L_{i,S}(t) as Z_{S}(t) * v_i / (t-\omega^i)
                     where:
                     - Z_{S}(t) = \prod_{j} (t-\omega^j) = (t^m-1), and
                     - v_{i} = 1 / \prod_{j \neq i} (\omega^i-\omega^j).
                     Below we use the fact that v_{0} = 1/m and v_{i+1} = \omega * v_{i}.
                     */

                    const value_type Z = (t.pow(m)) - value_type::one();
                    value_type l = Z * value_type(m).inversed();
                    value_type r = value_type::one();
                    for (std::size_t i = 0; i < m; ++i) {
                        u[i] = l * (t - r).inversed();
                        l *= omega;
                        r *= omega;
                    }

                    return u;
                }
            }    // namespace detail
        }        // namespace math
    }            // namespace actor
}    // namespace nil

#endif    // ALGEBRA_FFT_BASIC_RADIX2_DOMAIN_AUX_HPP
