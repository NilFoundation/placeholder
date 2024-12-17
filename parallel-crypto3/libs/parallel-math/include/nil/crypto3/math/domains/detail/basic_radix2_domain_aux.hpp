//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#ifndef PARALLEL_CRYPTO3_MATH_BASIC_RADIX2_DOMAIN_AUX_HPP
#define PARALLEL_CRYPTO3_MATH_BASIC_RADIX2_DOMAIN_AUX_HPP

#ifdef CRYPTO3_MATH_BASIC_RADIX2_DOMAIN_AUX_HPP
#error "You're mixing parallel and non-parallel crypto3 versions"
#endif

#include <nil/crypto3/math/detail/global_queue.hpp>

#include <algorithm>
#include <memory>
#include <vector>

#include <functional>
#include <sycl/sycl.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/detail/field_utils.hpp>

#include <nil/actor/core/thread_pool.hpp>
#include <nil/actor/core/parallelization_utils.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {

            template<typename FieldValueType, typename Allocator>
            class polynomial_dfs;

            namespace detail {

                /*
                 * Building caches for fft operations
                */
                template<typename FieldType, typename Allocator = std::allocator<typename FieldType::value_type>>
                void create_fft_cache(
                        const std::size_t size,
                        const typename FieldType::value_type &omega,
                        std::vector<typename FieldType::value_type, Allocator> &cache) {
                    typedef typename FieldType::value_type value_type;
                    cache.resize(size, FieldType::value_type::zero());
                    wait_for_all(parallel_run_in_chunks<void>(
                        size,
                        [&cache, &omega](std::size_t begin, std::size_t end) {
                            cache[begin] = omega.pow(begin);
                            for (std::size_t i = begin + 1; i < end; ++i) {
                                cache[i] = cache[i - 1] * omega;
                            }
                        }, ThreadPool::PoolLevel::LOW));
                }

                /*
                 * Below we make use of pseudocode from [CLRS 2n Ed, pp. 864].
                 * Also, note that it's the caller's responsibility to multiply by 1/N.
                 */
                template<typename FieldType, typename Range, typename Allocator = std::allocator<typename FieldType::value_type>>
                void basic_radix2_fft_cached(
                    Range &a,
                    sycl::buffer<typename FieldType::value_type, 1> &omega_cache
                ) {
                    typedef typename std::iterator_traits<decltype(std::begin(std::declval<Range>()))>::value_type
                        value_type;
                    BOOST_STATIC_ASSERT(algebra::is_field<FieldType>::value);

                    // It now supports curve elements too, should probably some other assertion about the field type and value type
                    // BOOST_STATIC_ASSERT(std::is_same<typename FieldType::value_type, value_type>::value);

                    const std::size_t n = a.size(), logn = log2(n);
                    if (n != (1u << logn))
                        throw std::invalid_argument("expected n == (1u << logn)");

                    std::shared_ptr<sycl::buffer<value_type, 1>> val_buf;
                    if constexpr (std::is_same_v<Range, polynomial_dfs<value_type, Allocator>>) {
                        val_buf = a.val_buf;
                    } else {
                        val_buf = std::make_shared<sycl::buffer<value_type, 1>>(
                            a.data(), sycl::range<1>(n), sycl::property::buffer::use_host_ptr{}
                        );
                    }
                    writeback_scope<value_type> writeback_scope(val_buf);

                    // swapping in place (from Storer's book)
                    // We can parallelize this look, since k and rk are pairs, they will never intersect.
                    GLOBAL_QUEUE.submit([&](sycl::handler &cgh) {
                        auto a_acc = val_buf->template get_access<sycl::access::mode::read_write>(cgh);
                        cgh.parallel_for(sycl::range<1>(n), [=](sycl::id<1> idx) {
                            const std::size_t ridx = crypto3::math::detail::bitreverse(idx, logn);
                            if (idx < ridx) {
                                std::swap(a_acc[idx], a_acc[ridx]);
                            }
                        });
                    });
                    GLOBAL_QUEUE.wait();
                    // invariant: m = 2^{s-1}
                    for (std::size_t s = 1, m = 1, inc = n / 2; s <= logn; ++s, m <<= 1, inc >>= 1) {
                        const size_t count_k = n / (2 * m) + (n % (2 * m) ? 1 : 0);
                        GLOBAL_QUEUE.submit([&](sycl::handler &cgh) {
                            auto a_acc = val_buf->template get_access<sycl::access::mode::read_write>(cgh);
                            auto omega_cache_acc = omega_cache.template get_access<sycl::access::mode::read>(cgh);
                            cgh.parallel_for(sycl::range<1>(count_k * m), [=](sycl::id<1> index) {
                                const std::size_t k = (index / m) * m * 2;
                                const std::size_t j = index % m;
                                const std::size_t idx = j * inc;
                                const value_type t = a_acc[k + j + m] * omega_cache_acc[idx];
                                a_acc[k + j + m] = a_acc[k + j] - t;
                                a_acc[k + j] += t;
                            });
                        });
                        GLOBAL_QUEUE.wait();
                    }
                }

                /**
                 * Note that it's the caller's responsibility to multiply by 1/N.
                 */
                template<typename FieldType, typename Range, typename Allocator = std::allocator<typename FieldType::value_type>>
                void basic_radix2_fft(
                    Range &a, const typename FieldType::value_type &omega,
                    std::shared_ptr<sycl::buffer<typename FieldType::value_type, 1>> omega_cache = nullptr
                ) {
                    using polynomial_dfs_type = polynomial_dfs<typename FieldType::value_type, Allocator>;
                    if (omega_cache == nullptr) {
                        std::vector<typename FieldType::value_type, Allocator> omega_powers;
                        create_fft_cache<FieldType, Allocator>(a.size(), omega, omega_powers);
                        sycl::buffer<typename FieldType::value_type, 1> omega_cache_buf(
                            omega_powers.data(), sycl::range<1>(a.size()), sycl::property::buffer::use_host_ptr{}
                        );
                        omega_cache_buf.set_write_back(false);
                        basic_radix2_fft_cached<FieldType>(a, omega_cache_buf);
                    } else {
                        basic_radix2_fft_cached<FieldType>(a, *omega_cache);
                    }
                }

                /**
                 * Compute the m Lagrange coefficients, relative to the set S={omega^{0},...,omega^{m-1}}, at the
                 * field element t.
                 */
                template<typename FieldType, typename Allocator = std::allocator<typename FieldType::value_type>>
                std::vector<typename FieldType::value_type, Allocator>
                    basic_radix2_evaluate_all_lagrange_polynomials(const std::size_t m,
                                                                   const typename FieldType::value_type &t) {
                    typedef typename FieldType::value_type value_type;

                    if (m == 1) {
                        return std::vector<value_type, Allocator>(1, value_type::one());
                    }

                    if (m != (1u << static_cast<std::size_t>(std::ceil(std::log2(m)))))
                        throw std::invalid_argument("expected m == (1u << log2(m))");

                    const value_type omega = unity_root<FieldType>(m);

                    std::vector<value_type, Allocator> u(m, value_type::zero());

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
        }        // namespace fft
    }            // namespace crypto3
}    // namespace nil

#endif    // PARALLEL_CRYPTO3_MATH_BASIC_RADIX2_DOMAIN_AUX_HPP
