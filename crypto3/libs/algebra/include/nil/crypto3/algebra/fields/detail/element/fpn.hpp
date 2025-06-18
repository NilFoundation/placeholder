//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FPN_HPP
#define CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FPN_HPP

#include <concepts>
#include <stdexcept>
#include <type_traits>

#include <boost/functional/hash.hpp>

#include <nil/crypto3/algebra/fields/detail/element/operations.hpp>
#include <nil/crypto3/algebra/fields/detail/exponentiation.hpp>

#include <nil/crypto3/multiprecision/detail/big_mod/modular_ops/babybear_simd.hpp>

namespace nil::crypto3::marshalling::types::detail {
    template<typename FieldValueType>
    typename std::enable_if<algebra::is_extended_field_element<FieldValueType>::value,
                            std::array<typename FieldValueType::field_type::integral_type,
                                       FieldValueType::field_type::arity>>::type
    fill_field_data(const FieldValueType &field_elem);
}

namespace nil::crypto3::algebra::fields {
    struct babybear;
}

namespace nil::crypto3::algebra::fields::detail {
    template<typename T>
    concept BinomialFieldExtensionParams = requires(T a) {
        { T::dimension } -> std::convertible_to<std::size_t>;
        typename T::field_type;
        typename T::base_field_type;
        {
            T::non_residue
        } -> std::convertible_to<typename T::base_field_type::value_type>;
        {
            T::dim_unity_root
        } -> std::convertible_to<typename T::base_field_type::value_type>;
    } && is_field<typename T::base_field_type>::value;

    struct FieldArchetype;

    struct FieldValueArchetype {
      private:
        using self = FieldValueArchetype;

      public:
        using field_type = FieldArchetype;

        static constexpr self zero() { return {}; }
        static constexpr self one() { return {}; }
        constexpr std::strong_ordering operator<=>(const self &) const = default;
        constexpr self operator*(const self &) const { return {}; }
        constexpr self &operator*=(const self &) { return *this; }
        constexpr self operator+(const self &) const { return {}; }
        constexpr self &operator+=(const self &) { return *this; }
        constexpr self inversed() const { return *this; }
        template<std::integral PowerType>
        constexpr self pow(const PowerType &) const {
            return *this;
        }
    };

    struct FieldArchetype {
        using value_type = FieldValueArchetype;
        constexpr static std::size_t value_bits = 10;
        struct integral_type {};
        constexpr static std::size_t modulus_bits = 20;
        struct modular_type {};
        constexpr static std::size_t arity = 3;
    };

    struct BinomialFieldExtensionParamsArchetype {
        constexpr static std::size_t dimension = 3;
        struct field_type {};
        using base_field_type = FieldArchetype;
        constexpr static base_field_type::value_type non_residue{};
        constexpr static base_field_type::value_type dim_unity_root{};
    };

    static_assert(BinomialFieldExtensionParams<BinomialFieldExtensionParamsArchetype>);

    // This is a generic class for binomial extension.
    // It works when Params::dimension divides (modulus - 1).
    // Unlike fp2 and fp3 multiplication and inversion are not optimized for specific
    // dimension. Also the parameters structure is a bit different.
    template<BinomialFieldExtensionParams Params>
    class element_fpn {
      public:
        using field_type = typename Params::field_type;
        using base_field_type = typename Params::base_field_type;
        using underlying_type = typename Params::base_field_type::value_type;
        constexpr static std::size_t dimension = Params::dimension;

      private:
        using data_type = std::array<underlying_type, dimension>;
        data_type data;

      public:
        constexpr element_fpn() : element_fpn(underlying_type::zero()) {}

        constexpr element_fpn(const data_type &in_data) : data(in_data) {}

        constexpr element_fpn(const underlying_type &a) {
            data[0] = a;
            for (std::size_t i = 1; i < dimension; ++i) {
                data[i] = underlying_type::zero();
            }
        }

        template<std::size_t Bits>
        constexpr element_fpn(const nil::crypto3::multiprecision::big_uint<Bits> &data)
            : element_fpn(underlying_type(data)) {}

        template<std::integral Number>
        constexpr element_fpn(const Number &data) : element_fpn(underlying_type(data)) {}

        constexpr typename base_field_type::integral_type to_integral() const {
            for (std::size_t i = 1; i < dimension; ++i) {
                if (!data[i].is_zero()) {
                    throw std::runtime_error(
                        "Trying to convert to integral a value that is not a subfield "
                        "element");
                }
            }
            return data[0].to_integral();
        }

        // Creating a zero is a fairly slow operation and is called very often, so we
        // must return a reference to the same static object every time.
        constexpr static const element_fpn &zero();
        constexpr static const element_fpn &one();

        constexpr bool is_zero() const { return *this == zero(); }
        constexpr bool is_one() const { return *this == one(); }

        constexpr std::strong_ordering operator<=>(const element_fpn &B) const = default;

        underlying_type binomial_extension_coefficient(std::size_t index) const {
            return data.at(index);
        }

        constexpr element_fpn operator+(const element_fpn &B) const {
            element_fpn result = *this;
            result += B;
            return result;
        }

        constexpr element_fpn operator-(const element_fpn &B) const {
            element_fpn result = *this;
            result -= B;
            return result;
        }

        constexpr element_fpn &operator+=(const element_fpn &B) {
            for (std::size_t i = 0; i < dimension; ++i) {
                data[i] += B.data[i];
            }
            return *this;
        }

        constexpr element_fpn &operator-=(const element_fpn &B) {
            for (std::size_t i = 0; i < dimension; ++i) {
                data[i] -= B.data[i];
            }
            return *this;
        }

        constexpr void negate_inplace() {
            for (auto &c : data) {
                c.negate_inplace();
            }
        }

        constexpr element_fpn operator-() const {
            element_fpn result = *this;
            result.negate_inplace();
            return result;
        }

        constexpr element_fpn operator*(const element_fpn &B) const {
            if constexpr (dimension == 4 &&
                            std::is_same_v<typename underlying_type::field_type,
                                            babybear>) {
                return nil::crypto3::multiprecision::detail::babybear::babybear_fp4_vec_mul(
                    data, B.data);
            }
            element_fpn result;
            for (std::size_t j = 0; j < dimension; ++j) {
                result.data[j] += data[0] * B.data[j];
            }
            for (std::size_t i = 1; i < dimension; ++i) {
                auto di_non_res = data[i] * Params::non_residue;
                for (std::size_t j = 0; j < dimension; ++j) {
                    if (i + j >= dimension) {
                        result.data[i + j - dimension] += di_non_res * B.data[j];
                    } else {
                        result.data[i + j] += data[i] * B.data[j];
                    }
                }
            }
            return result;
        }

        constexpr element_fpn &operator*=(const element_fpn &B) {
            *this = *this * B;
            return *this;
        }

        constexpr element_fpn &operator*=(const underlying_type &b) {
            for (auto &c : data) {
                c *= b;
            }
            return *this;
        }

        constexpr element_fpn operator*(const underlying_type &b) const {
            element_fpn result = *this;
            result *= b;
            return result;
        }

        constexpr element_fpn &operator/=(const element_fpn &B) {
            *this *= B.inversed();
            return *this;
        }

        constexpr element_fpn operator/(const element_fpn &B) const {
            element_fpn result = *this;
            result /= B;
            return result;
        }

        constexpr element_fpn &operator++() {
            data[0]++;
            return *this;
        }

        constexpr element_fpn operator++(int) {
            element_fpn temp(*this);
            ++*this;
            return temp;
        }

        constexpr element_fpn &operator--() {
            data[0]--;
            return *this;
        }

        constexpr element_fpn operator--(int) {
            element_fpn temp(*this);
            --*this;
            return temp;
        }

        constexpr element_fpn doubled() const {
            element_fpn result = *this;
            for (auto &c : result.data) {
                c.double_inplace();
            }
            return result;
        }

        constexpr void double_inplace() {
            for (auto &c : data) {
                c.double_inplace();
            }
        }

        constexpr element_fpn squared() const { return (*this) * (*this); }

        constexpr void square_inplace() { (*this) *= (*this); }

        template<multiprecision::integral PowerType>
        constexpr element_fpn pow(const PowerType &pwr) const {
            if constexpr (std::is_signed_v<PowerType>) {
                if (pwr < 0) {
                    return power(*this, -pwr).inversed();
                }
            }
            return power(*this, pwr);
        }

        constexpr element_fpn inversed() const {
            auto f = one();
            for (std::size_t i = 1; i < dimension; ++i) {
                f = (f * *this).Frobenius_map(1);
            }

            typename base_field_type::value_type g{};
            for (std::size_t i = 1; i < dimension; ++i) {
                g += data[i] * f.data[dimension - i];
            }
            g *= Params::non_residue;
            g += data[0] * f.data[0];
            assert(element_fpn(g) == *this * f);

            return f * g.inversed();
        }

        template<std::integral PowerType>
        constexpr element_fpn Frobenius_map(const PowerType &pwr) const {
            if (pwr == 0) {
                return *this;
            } else if (pwr >= dimension) {
                return Frobenius_map(pwr % dimension);
            }

            auto z0 = Params::dim_unity_root.pow(pwr);
            auto z = Params::base_field_type::value_type::one();

            element_fpn result{};
            for (size_t i = 0; i < dimension; ++i) {
                result.data[i] = data[i] * z;
                z *= z0;
            }
            return result;
        }

        friend std::ostream &operator<<(std::ostream &os, const element_fpn &elem) {
            os << '[';
            bool first = true;
            for (const auto &c : elem.data) {
                if (!first) {
                    os << ", ";
                }
                os << c;
                first = false;
            }
            os << ']';
            return os;
        }

        friend std::hash<element_fpn>;
        template<typename FieldValueType>
        friend typename std::enable_if<
            algebra::is_extended_field_element<FieldValueType>::value,
            std::array<typename FieldValueType::field_type::integral_type,
                       FieldValueType::field_type::arity>>::type
        nil::crypto3::marshalling::types::detail::fill_field_data(
            const FieldValueType &field_elem);
    };

    template<BinomialFieldExtensionParams Params>
    constexpr element_fpn<Params> operator*(
        const typename Params::base_field_type::value_type &lhs,
        const element_fpn<Params> &rhs) {
        return rhs * lhs;
    }

    namespace element_fpn_details {
        // These constexpr static variables can not be members of element_fpn, because
        // element_fpn is incomplete type until the end of its declaration.
        template<BinomialFieldExtensionParams Params>
        constexpr static element_fpn<Params> zero_instance(
            Params::base_field_type::value_type::zero());

        template<BinomialFieldExtensionParams Params>
        constexpr static element_fpn<Params> one_instance(
            Params::base_field_type::value_type::one());
    }  // namespace element_fpn_details

    template<BinomialFieldExtensionParams Params>
    constexpr const element_fpn<Params> &element_fpn<Params>::zero() {
        return element_fpn_details::zero_instance<Params>;
    }

    template<BinomialFieldExtensionParams Params>
    constexpr const element_fpn<Params> &element_fpn<Params>::one() {
        return element_fpn_details::one_instance<Params>;
    }

    static_assert(
        is_field_element<element_fpn<BinomialFieldExtensionParamsArchetype>>::value);
    static_assert(is_extended_field_element<
                  element_fpn<BinomialFieldExtensionParamsArchetype>>::value);
}  // namespace nil::crypto3::algebra::fields::detail

template<nil::crypto3::algebra::fields::detail::BinomialFieldExtensionParams Params>
struct std::hash<nil::crypto3::algebra::fields::detail::element_fpn<Params>> {
    std::hash<typename nil::crypto3::algebra::fields::detail::element_fpn<
        Params>::underlying_type>
        hasher;
    size_t operator()(
        const nil::crypto3::algebra::fields::detail::element_fpn<Params> &elem) const {
        std::size_t result = 0;
        for (const auto &c : elem.data) {
            boost::hash_combine(result, hasher(c));
        }
        return result;
    }
};

#endif  // CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FPN_HPP
