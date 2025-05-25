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

#ifndef CRYPTO3_MATH_POLYMORPHIC_POLYNOMIAL_DFS_HPP
#define CRYPTO3_MATH_POLYMORPHIC_POLYNOMIAL_DFS_HPP

#include <algorithm>
#include <iterator>
#include <limits>
#include <memory>
#include <ostream>
#include <unordered_map>
#include <variant>
#include <vector>

#include "polymorphic_polynomial.hpp"
#include "polynomial_dfs.hpp"

#include <nil/crypto3/bench/scoped_profiler.hpp>

namespace nil::crypto3::math {
    template<typename FieldType>
    class polymorphic_polynomial_dfs {
      public:
        using value_type = typename FieldType::value_type;
        using small_field_value_type = typename FieldType::small_subfield::value_type;

        using size_type = std::size_t;
        using small_val = polynomial_dfs<small_field_value_type>;
        using big_val = polynomial_dfs<value_type>;

        using polynomial_type = polymorphic_polynomial<FieldType>;

        mutable std::variant<small_val, big_val> val;

        polymorphic_polynomial_dfs() {}

        polymorphic_polynomial_dfs(const small_val& v) : val(v) {}
        polymorphic_polynomial_dfs(small_val&& v) : val(std::move(v)) {}

        polymorphic_polynomial_dfs(const big_val& v) : val(v) {}
        polymorphic_polynomial_dfs(big_val&& v) : val(std::move(v)) {}

        explicit polymorphic_polynomial_dfs(size_t d, size_type n)
            : val(small_val(d, n)) {}

        polymorphic_polynomial_dfs(size_t d, size_type n, const small_field_value_type& x)
            : val(small_val(d, n, x)) {}

        size_type size() const noexcept {
            return std::visit([](const auto& v) { return v.size(); }, val);
        }

        size_type degree() const noexcept {
            return std::visit([](const auto& v) { return v.degree(); }, val);
        }

        size_type max_degree() const noexcept { return this->size(); }

        void clear() noexcept { val.clear(); }

        void resize(size_type sz) {
            std::visit([sz](auto& v) { v.resize(sz); }, val);
        }

        value_type operator[](size_type s) const {
            return std::visit([s](const auto& v) { return value_type(v[s]); }, val);
        }

        template<typename EvaluationFieldValueType>
        EvaluationFieldValueType evaluate(const EvaluationFieldValueType& value) const {
            return std::visit([value](const auto& v) { return v.evaluate(value); }, val);
        }

        bool is_zero() const {
            return std::visit([](const auto& v) { return v.is_zero(); }, val);
        }

        bool is_one() const {
            return std::visit([](const auto& v) { return v.is_one(); }, val);
        }

        inline static polymorphic_polynomial_dfs zero() {
            return polymorphic_polynomial_dfs();
        }

        inline static polymorphic_polynomial_dfs one() {
            return polymorphic_polynomial_dfs(0, size_type(1),
                                              small_field_value_type::one());
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
        polymorphic_polynomial_dfs& operator+=(const value_type& c) { ensure_big() += c; }

        polymorphic_polynomial_dfs& operator-=(const value_type& c) { ensure_big() -= c; }

        polymorphic_polynomial_dfs& operator*=(const value_type& c) { ensure_big() *= c; }

        template<typename ContainerType>
        void from_coefficients(const ContainerType& tmp) {
            ensure_big().from_coefficients(tmp);
        }

        polynomial_type coefficients() const {
            return std::visit(
                [](const auto& v) { return polynomial_type(v.coefficients()); }, val);
        }
    };

    // Used in the unit tests, so we can use BOOST_CHECK_EQUALS, and see
    // the values of polynomials, when the check fails.
    template<typename value_type, typename = typename std::enable_if<
                                      detail::is_field_element<value_type>::value>::type>
    std::ostream& operator<<(std::ostream& os,
                             const polymorphic_polynomial_dfs<value_type>& poly) {
        return std::visit([&os](const auto& v) { return os << v; }, poly.val);
    }
}  // namespace nil::crypto3::math

// As our operator== returns false for polynomials with different sizes, the same will
// happen here, resized polynomial will have a different hash from the initial one.
template<typename value_type>
struct std::hash<nil::crypto3::math::polymorphic_polynomial_dfs<value_type>> {
    std::hash<value_type> value_hasher;

    std::size_t operator()(
        const nil::crypto3::math::polymorphic_polynomial_dfs<value_type>& poly) const {
        std::size_t result = std::hash<std::size_t>()(poly.val.index());
        boost::hash_combine(
            result,
            std::visit(
                [](const auto& v) { return std::hash<std::decay_t<decltype(v)>>()(v); },
                poly.val));
        return result;
    }
};

#endif  // CRYPTO3_MATH_POLYMORPHIC_POLYNOMIAL_DFS_HPP
