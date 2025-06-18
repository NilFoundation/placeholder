//---------------------------------------------------------------------------//
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

#ifndef CRYPTO3_MATH_POLYNOMIAL_POLYMORPHIC_POLYNOMIAL_HPP
#define CRYPTO3_MATH_POLYNOMIAL_POLYMORPHIC_POLYNOMIAL_HPP

#include <algorithm>
#include <ranges>
#include <vector>
#include <variant>

#include <nil/crypto3/math/polynomial/polynomial.hpp>

#include <nil/crypto3/algebra/fields/utils.hpp>

namespace nil::crypto3::math {
    template<typename FieldType>
    class polymorphic_polynomial {
      public:
        using value_type = typename FieldType::value_type;
        using small_field_value_type = typename FieldType::small_subfield::value_type;

        using size_type = std::size_t;
        using small_val = polynomial<small_field_value_type>;
        using big_val = polynomial<value_type>;

        mutable std::variant<small_val, big_val> val;

        polymorphic_polynomial() {}

        polymorphic_polynomial(std::vector<value_type>&& v)
            : val(big_val(std::move(v))) {}
        polymorphic_polynomial(std::vector<small_field_value_type>&& v)
            : val(small_val(std::move(v))) {}

        size_type size() const noexcept {
            return std::visit([](const auto& v) { return v.size(); }, val);
        }

        value_type operator[](size_type s) const {
            return std::visit([s](const auto& v) { return value_type(v[s]); }, val);
        }

        auto& get_big() {
            if (!std::holds_alternative<big_val>(val)) {
                throw std::logic_error(
                    "Polymorphic vector holds small field but big field expected");
            }
            return std::get<big_val>(val);
        }

        const auto& get_big() const {
            if (!std::holds_alternative<big_val>(val)) {
                throw std::logic_error(
                    "Polymorphic vector holds small field but big field expected");
            }
            return std::get<big_val>(val);
        }

        void ensure_big_impl() const {
            if (!std::holds_alternative<big_val>(val)) {
                val = big_val(std::get<small_val>(val));
            }
        }

        auto& ensure_big() {
            ensure_big_impl();
            return get_big();
        }

        const auto& ensure_big() const {
            ensure_big_impl();
            return get_big();
        }

        operator big_val&&() && {
            ensure_big();
            return std::move(get_big());
        }

        polymorphic_polynomial& operator*=(value_type a) {
            if (std::holds_alternative<big_val>(val)) {
                get_big() *= a;
            } else {
                const auto& small = std::get<small_val>(val);
                big_val p(small.size());
                parallel_for(0, small.size(),
                             [&a, &p, &small](std::size_t i) { p[i] = small[i] * a; });
                val = p;
            }
            return *this;
        }

        friend big_val& operator+=(big_val& a, const polymorphic_polynomial &b) {;
            a += b.ensure_big();
            return a;
        }

        template<std::ranges::range Range>
            requires(std::ranges::sized_range<Range>)
        algebra::fields::choose_extension_field_t<value_type,
                                                  std::ranges::range_value_t<Range>>
        evaluate_powers(const Range& r) const {
            return std::visit(
                [&r](const auto& v) {
                    return algebra::fields::choose_extension_field_t<
                        value_type, std::ranges::range_value_t<Range>>(
                        v.evaluate_powers(r));
                },
                val);
        }

        template<typename PointFieldValueType>
        algebra::fields::choose_extension_field_t<value_type, PointFieldValueType>
        evaluate(const PointFieldValueType& a) const {
            return std::visit(
                [a](const auto& v) {
                    return algebra::fields::choose_extension_field_t<value_type,
                                                                     PointFieldValueType>(
                        v.evaluate(a));
                },
                val);
        }
    };

    // Used in the unit tests, so we can use BOOST_CHECK_EQUALS, and see
    // the values of polymorphic_polynomials, when the check fails.
    template<typename value_type, typename = typename std::enable_if<
                                      detail::is_field_element<value_type>::value>::type>
    std::ostream& operator<<(std::ostream& os,
                             const polymorphic_polynomial<value_type>& poly) {
        return std::visit([&os](const auto &v){ os << v; }, poly.val);
    }
}  // namespace nil::crypto3::math

#endif  // CRYPTO3_MATH_POLYNOMIAL_POLYMORPHIC_POLYNOMIAL_HPP