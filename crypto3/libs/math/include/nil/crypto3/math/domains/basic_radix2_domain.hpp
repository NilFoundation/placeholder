//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_MATH_BASIC_RADIX2_DOMAIN_HPP
#define CRYPTO3_MATH_BASIC_RADIX2_DOMAIN_HPP

#include <vector>

#include <nil/crypto3/math/detail/field_utils.hpp>

#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/domains/detail/basic_radix2_domain_aux.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/actor/core/parallelization_utils.hpp>

#include <nil/crypto3/bench/scoped_profiler.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {

            using namespace nil::crypto3::algebra;

            template<typename FieldType, typename ValueType>
            class evaluation_domain;

            template<typename FieldType, typename ValueType = typename FieldType::value_type>
            class basic_radix2_domain : public evaluation_domain<FieldType, ValueType> {
                typedef typename FieldType::value_type field_value_type;
                typedef ValueType value_type;
                typedef std::pair<std::vector<field_value_type>, std::vector<field_value_type>> cache_type;
                std::shared_ptr<cache_type> fft_cache;

                void create_fft_cache() {
                    fft_cache = std::make_shared<cache_type>(std::vector<field_value_type>(),
                                                             std::vector<field_value_type>());
                    detail::create_fft_cache<FieldType>(this->m, omega, fft_cache->first);
                    detail::create_fft_cache<FieldType>(this->m, omega.inversed(), fft_cache->second);
                }

            public:
                typedef FieldType field_type;

                field_value_type omega;

                basic_radix2_domain(const std::size_t m)
                        : evaluation_domain<FieldType, ValueType>(m),
                          omega(unity_root<FieldType>(m)) {
                    if (m <= 1)
                        throw std::invalid_argument("basic_radix2(): expected m > 1");

                    if (!std::is_same<field_value_type, std::complex<double>>::value) {
                        const std::size_t logm = static_cast<std::size_t>(std::ceil(std::log2(m)));
                        if (logm > (fields::arithmetic_params<FieldType>::two_adicity))
                            throw std::invalid_argument(
                                "basic_radix2(): expected logm <= "
                                "fields::arithmetic_params<FieldType>::two_adicity");
                    }

                    // We need to always create fft cache, we cannot create it when needed in parallel environment.
                    create_fft_cache();
                }

                void fft(std::vector<value_type> &a) override {
                    if (a.size() != this->m) {
                        if (a.size() < this->m) {
                            a.resize(this->m, value_type::zero());
                        } else {
                            throw std::invalid_argument("basic_radix2: expected a.size() <= this->m");
                        }
                    }

                    detail::basic_radix2_fft_cached<FieldType>(a, fft_cache->first);
                }

                void resize_to_domain_size(std::vector<std::vector<value_type>> &a) {
                    if (a[0].size() == this->m) {
                        return;
                    }

                    PROFILE_SCOPE("Resize to domain size {} vectors from size {} to {}",
                                  a.size(), a[0].size(), this->m);

                    for (auto& p: a) {
                        if (p.size() != this->m) {
                            if (p.size() < this->m) {
                                p.resize(this->m, value_type::zero());
                            } else {
                                throw std::invalid_argument("Expected polynomail size <= domain size");
                            }
                        }
                    }
                }

                /** \brief Batch version of the 'fft' function
                 *  \param[in] polys - Each element of 'polys' represents coefficients of a polynomial.
                 *                  So if we have 100 polynomials of size 2^20 to FFT, the dimensions of
                 *                  'polys' will be [100x2^20].
                 */
                void batch_fft(std::vector<std::vector<value_type>> &polys) override {
                    if (polys.size() == 0)
                        return;
                    resize_to_domain_size(polys);

                    nil::crypto3::parallel_foreach(polys.begin(), polys.end(),
                        [this](std::vector<value_type>& p) {
                            detail::basic_radix2_fft_cached<FieldType>(p, this->fft_cache->first);
                    }, ThreadPool::PoolLevel::HIGH);
                }

                /** \brief Batch version of the 'inverse_fft' function
                 *  \param[in] polys - Each element of 'polys' represents coefficients of a polynomial.
                 *                  So if we have 100 polynomials of size 2^20 to FFT, the dimensions of
                 *                  'polys' will be [100x2^20].
                 */
                void batch_inverse_fft(std::vector<std::vector<value_type>> &polys) override {
                    if (polys.size() == 0)
                        return;
                    resize_to_domain_size(polys);

                    const field_value_type sconst = field_value_type(this->m).inversed();
                    nil::crypto3::parallel_foreach(polys.begin(), polys.end(),
                        [&sconst, this](std::vector<value_type>& p) {
                            detail::basic_radix2_fft_cached<FieldType>(p, this->fft_cache->second);
                            nil::crypto3::parallel_foreach(p.begin(), p.end(), [&sconst](value_type& p_i) {
                                p_i *= sconst;
                            });
                    }, ThreadPool::PoolLevel::HIGH);
                }

                void inverse_fft(std::vector<value_type> &a) override {
                    if (a.size() != this->m) {
                        if (a.size() < this->m) {
                            a.resize(this->m, value_type::zero());
                        } else {
                            throw std::invalid_argument("basic_radix2: expected a.size() == this->m");
                        }
                    }

                    detail::basic_radix2_fft_cached<FieldType>(a, fft_cache->second);

                    const field_value_type sconst = field_value_type(this->m).inversed();
                    nil::crypto3::parallel_foreach(a.begin(), a.end(), [&sconst](value_type& a_i){
                        a_i *= sconst;
                    });
                }

                std::vector<field_value_type> evaluate_all_lagrange_polynomials(const field_value_type &t) override {
                    return detail::basic_radix2_evaluate_all_lagrange_polynomials<FieldType>(this->m, t);
                }

                std::vector<value_type> evaluate_all_lagrange_polynomials(
                        const typename std::vector<value_type>::const_iterator &t_powers_begin,
                        const typename std::vector<value_type>::const_iterator &t_powers_end) override {
                    if (std::size_t(std::distance(t_powers_begin, t_powers_end)) < this->m) {
                        throw std::invalid_argument(
                                "basic_radix2: expected std::distance(t_powers_begin, t_powers_end) >= this->m");
                    }
                    std::vector<value_type> tmp(t_powers_begin, t_powers_begin + this->m);
                    this->inverse_fft(tmp);
                    return tmp;
                }

                const field_value_type &get_unity_root() override {
                    return omega;
                }

                field_value_type get_domain_element(const std::size_t idx) override {
                    return omega.pow(idx);
                }

                field_value_type compute_vanishing_polynomial(const field_value_type &t) override {
                    return (t.pow(this->m)) - field_value_type::one();
                }

                polynomial<field_value_type> get_vanishing_polynomial() override {
                    polynomial<field_value_type> z(this->m + 1, field_value_type::zero());
                    z[this->m] = field_value_type::one();
                    z[0] = -field_value_type::one();
                    return z;
                }

                void add_poly_z(const field_value_type &coeff, std::vector<field_value_type> &H) override {
                    if (H.size() != this->m + 1)
                        throw std::invalid_argument("basic_radix2: expected H.size() == this->m+1");

                    H[this->m] += coeff;
                    H[0] -= coeff;
                }

                void divide_by_z_on_coset(std::vector<field_value_type> &P) override {
                    const field_value_type coset = fields::arithmetic_params<FieldType>::multiplicative_generator;
                    const field_value_type Z_inverse_at_coset = this->compute_vanishing_polynomial(coset).inversed();
                    nil::crypto3::parallel_foreach(P.begin(), P.end(), [&Z_inverse_at_coset](field_value_type& v){v *= Z_inverse_at_coset;});
                }

                bool operator==(const basic_radix2_domain &rhs) const {
                    return isEqual(rhs) && omega == rhs.omega;
                }

                bool operator!=(const basic_radix2_domain &rhs) const {
                    return !(*this == rhs);
                }
            };
        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FFT_BASIC_RADIX2_DOMAIN_HPP
