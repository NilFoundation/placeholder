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

#ifndef CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FP_HPP
#define CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FP_HPP

#include <iostream>

#include <nil/crypto3/algebra/fields/detail/exponentiation.hpp>
#include <nil/crypto3/algebra/fields/detail/element/operations.hpp>

#include <nil/crypto3/multiprecision/big_mod.hpp>
#include <nil/crypto3/multiprecision/big_uint.hpp>
#include <nil/crypto3/multiprecision/pow.hpp>
#include <nil/crypto3/multiprecision/ressol.hpp>

#include <type_traits>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                namespace detail {
                    template<typename FieldParams>
                    class element_fp {
                        typedef FieldParams policy_type;

                      public:
                        typedef typename policy_type::field_type field_type;

                        typedef typename policy_type::modular_type modular_type;
                        typedef typename policy_type::integral_type integral_type;

                        constexpr static const integral_type modulus = policy_type::modulus;

                      private:
                        using data_type = modular_type;
                        data_type data;

                      public:
                        constexpr element_fp() = default;

                        constexpr element_fp(const data_type &data) : data(data) {}

                        constexpr element_fp(
                            const std::array<element_fp, 1> &coefficients)
                            : element_fp(coefficients[0]) {}

                        template<multiprecision::integral T>
                        constexpr element_fp(const T &data) : data(data) {}

                        constexpr typename field_type::integral_type to_integral() const {
                            return data.to_integral();
                        }

                        // Creating a zero is a fairly slow operation and is called very often, so we must return a
                        // reference to the same static object every time.
                        constexpr static const element_fp &zero();

                        constexpr static const element_fp &one();

                        constexpr bool is_zero() const {
                            return *this == zero();
                        }

                        constexpr bool is_one() const {
                            return *this == one();
                        }

                        constexpr auto operator<=>(const element_fp &B) const {
                            return to_integral() <=> B.to_integral();
                        }

                        constexpr bool operator==(const element_fp &B) const {
                            return data == B.data;
                        }

                        element_fp binomial_extension_coefficient(
                            std::size_t index) const {
                            if (index != 0) {
                                throw std::logic_error(
                                    "FP is degree 1 extension of itself, but trying to "
                                    "access more coefficients");
                            }
                            return *this;
                        }

                        constexpr element_fp operator+(const element_fp &B) const {
                            return element_fp(data + B.data);
                        }

                        constexpr element_fp operator-(const element_fp &B) const {
                            return element_fp(data - B.data);
                        }

                        constexpr element_fp &operator-=(const element_fp &B) {
                            data -= B.data;

                            return *this;
                        }

                        constexpr element_fp &operator+=(const element_fp &B) {
                            data += B.data;

                            return *this;
                        }

                        constexpr element_fp &operator*=(const element_fp &B) {
                            data *= B.data;

                            return *this;
                        }
                        constexpr element_fp &operator/=(const element_fp &B) {
                            data *= B.inversed().data;

                            return *this;
                        }

                        constexpr element_fp operator-() const {
                            return element_fp(-data);
                        }

                        constexpr void negate_inplace() {
                            data = -data;
                        }

                        constexpr element_fp operator/(const element_fp &B) const {
                            //                        return element_fp(data / B.data);
                            return element_fp(data * B.inversed().data);
                        }

                        constexpr element_fp operator*(const element_fp &B) const {
                            return element_fp(data * B.data);
                        }

                        constexpr element_fp &operator++() {
                            data += one().data;
                            return *this;
                        }

                        constexpr element_fp operator++(int) {
                            element_fp temp(*this);
                            ++*this;
                            return temp;
                        }

                        constexpr element_fp &operator--() {
                            data = data - modular_type(1u);
                            return *this;
                        }

                        constexpr element_fp operator--(int) {
                            element_fp temp(*this);
                            --*this;
                            return temp;
                        }

                        constexpr element_fp doubled() const {
                            return element_fp(data + data);
                        }

                        constexpr void double_inplace() {
                            data += data;
                        }

                        // If the element does not have a square root, this function must not be called.
                        // Call is_square() before using this function.
                        constexpr element_fp sqrt() const {
                            if (this->is_zero())
                                return zero();
                            element_fp result = ressol(data);
                            assert(!result.is_zero());
                            return result;
                        }

                        constexpr element_fp inversed() const {
                            return element_fp(inverse(data));
                        }

                        constexpr element_fp squared() const {
                            return element_fp(data * data);    // maybe can be done more effective
                        }

                        constexpr element_fp& square_inplace() {
                            data *= data;
                            return *this;
                        }


                        constexpr bool is_square() const {
                            element_fp tmp = this->pow(policy_type::group_order_minus_one_half);
                            return (tmp.is_one() || tmp.is_zero());
                        }

                        template<typename PowerType>
                        constexpr element_fp pow(const PowerType &pwr) const {
                            return element_fp(nil::crypto3::multiprecision::pow(data, pwr));
                        }

                        friend std::ostream &operator<<(std::ostream &os,
                                                        const element_fp &elem) {
                            os << elem.data;
                            return os;
                        }

                        friend std::hash<element_fp>;
                    };

                    template<typename FieldParams>
                    constexpr typename element_fp<FieldParams>::integral_type const element_fp<FieldParams>::modulus;

                    namespace element_fp_details {
                        // These constexpr static variables can not be members of element_fp, because
                        // element_fp is incomplete type until the end of its declaration.
                        template<typename FieldParams>
                        constexpr static element_fp<FieldParams> zero_instance = 0u;

                        template<typename FieldParams>
                        constexpr static element_fp<FieldParams> one_instance = 1u;
                    }

                    template<typename FieldParams>
                    constexpr const element_fp<FieldParams> &element_fp<FieldParams>::zero() {
                        return element_fp_details::zero_instance<FieldParams>;
                    }

                    template<typename FieldParams>
                    constexpr const element_fp<FieldParams> &element_fp<FieldParams>::one() {
                        return element_fp_details::one_instance<FieldParams>;
                    }
                }    // namespace detail
            }        // namespace fields
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

template<typename FieldParams>
struct std::hash<typename nil::crypto3::algebra::fields::detail::element_fp<FieldParams>> {
    std::hash<typename nil::crypto3::algebra::fields::detail::element_fp<FieldParams>::modular_type> hasher;

    size_t operator()(const nil::crypto3::algebra::fields::detail::element_fp<FieldParams> &elem) const {
        std::size_t result = hasher(elem.data);
        return result;
    }
};

#endif    // CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FP_HPP
