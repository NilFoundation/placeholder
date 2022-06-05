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

#ifndef ACTOR_MATH_BASIC_RADIX2_DOMAIN_HPP
#define ACTOR_MATH_BASIC_RADIX2_DOMAIN_HPP

#include <vector>

#include <nil/crypto3/math/detail/field_utils.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>

#include <nil/actor/math/domains/detail/basic_radix2_domain_aux.hpp>

namespace nil {
    namespace actor {
        namespace math {

            using namespace nil::crypto3::algebra;

            template<typename FieldType>
            class basic_radix2_domain : public crypto3::math::evaluation_domain<FieldType> {
                typedef typename FieldType::value_type value_type;

            public:
                typedef FieldType field_type;

                value_type omega;

                basic_radix2_domain(const std::size_t m) : crypto3::math::evaluation_domain<FieldType>(m) {
                    BOOST_ASSERT_MSG(m > 1, "basic_radix2(): expected m > 1");

                    if (!std::is_same<value_type, std::complex<double>>::value) {
                        const std::size_t logm = static_cast<std::size_t>(std::ceil(std::log2(m)));
                        BOOST_ASSERT_MSG(logm <= (fields::arithmetic_params<FieldType>::s),
                                         "basic_radix2(): expected logm <= fields::arithmetic_params<FieldType>::s");
                    }

                    omega = crypto3::math::unity_root<FieldType>(m);
                }

                void fft(std::vector<value_type> &a) {
                    if (a.size() != this->m) {
                        BOOST_ASSERT_MSG(a.size() >= this->m, "basic_radix2: expected a.size() == this->m");

                        a.resize(this->m, value_type(0));
                    }

                    detail::basic_radix2_fft<FieldType>(a, omega);
                }

                future<> inverse_fft(std::vector<value_type> &a) {
                    if (a.size() != this->m) {
                        BOOST_ASSERT_MSG(a.size() >= this->m, "basic_radix2: expected a.size() == this->m");

                        a.resize(this->m, value_type(0));
                    }

                    detail::basic_radix2_fft<FieldType>(a, omega.inversed());

                    const value_type sconst = value_type(a.size()).inversed();

                    detail::block_execution(this->m, smp::count, [sconst, &a](std::size_t begin, std::size_t end) {
                        for (std::size_t i = begin; i < end; i++) {
                            a[i] *= sconst;
                        }
                    }).get();

                    return make_ready_future<>();
                }

                std::vector<value_type> evaluate_all_lagrange_polynomials(const value_type &t) {
                    return detail::basic_radix2_evaluate_all_lagrange_polynomials<FieldType>(this->m, t);
                }

                value_type get_domain_element(const std::size_t idx) {
                    return omega.pow(idx);
                }

                value_type compute_vanishing_polynomial(const value_type &t) {
                    return (t.pow(this->m)) - value_type::one();
                }

                void add_poly_z(const value_type &coeff, std::vector<value_type> &H) {
                    BOOST_ASSERT_MSG(H.size() == this->m + 1, "basic_radix2: expected H.size() == this->m+1");

                    H[this->m] += coeff;
                    H[0] -= coeff;
                }

                future<> divide_by_z_on_coset(std::vector<value_type> &P) {
                    const value_type coset = fields::arithmetic_params<FieldType>::multiplicative_generator;
                    const value_type Z_inverse_at_coset = this->compute_vanishing_polynomial(coset).inversed();

                    detail::block_execution(this->m, smp::count, [&P](std::size_t begin, std::size_t end) {
                        for (std::size_t i = begin; i < end; i++) {
                            P[i] *= Z_inverse_at_coset;
                        }
                    }).get();

                    return make_ready_future<>();
                }

                bool operator==(const basic_radix2_domain &rhs) const {
                    return isEqual(rhs) && omega == rhs.omega;
                }

                bool operator!=(const basic_radix2_domain &rhs) const {
                    return !(*this == rhs);
                }
            };
        }    // namespace math
    }        // namespace actor
}    // namespace nil

#endif    // ALGEBRA_FFT_BASIC_RADIX2_DOMAIN_HPP
