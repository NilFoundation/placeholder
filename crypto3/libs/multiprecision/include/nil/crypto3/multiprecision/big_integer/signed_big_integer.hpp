#pragma once

// IWYU pragma: private; include "nil/crypto3/multiprecision/signed_big_integer/signed_big_integer.hpp"

#include <climits>
#include <cmath>
#include <cstring>
#include <string>
#include <type_traits>

// TODO(ioxid): replace with custom code
#include <boost/multiprecision/cpp_int.hpp>

#include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"
#include "nil/crypto3/multiprecision/big_integer/detail/assert.hpp"
#include "nil/crypto3/multiprecision/big_integer/detail/config.hpp"

namespace nil::crypto3::multiprecision {
    template<unsigned Bits_>
    class signed_big_integer {
      public:
        constexpr static unsigned Bits = Bits_;
        using self_type = signed_big_integer<Bits>;

        using unsigned_type = big_integer<Bits>;

        // Constructor

        inline constexpr signed_big_integer() noexcept {}

        template<unsigned Bits2>
        inline constexpr signed_big_integer(const big_integer<Bits2>& b) noexcept : m_abs(b) {}

        template<class T, std::enable_if_t<std::is_integral_v<T> && std::is_signed_v<T>, int> = 0>
        inline constexpr signed_big_integer(T val) noexcept : m_abs(abs(val)) {
            // for ADL
            using std::abs;
            if (val < 0) {
                negate();
            }
        }

        template<class T, std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, int> = 0>
        inline constexpr signed_big_integer(T val) noexcept : m_abs(val) {}

        template<unsigned Bits2>
        inline constexpr signed_big_integer(const signed_big_integer<Bits2>& other) noexcept
            : m_negative(other.negative()), m_abs(other.abs()) {}

        // Assignment

        template<unsigned Bits2>
        inline constexpr signed_big_integer& operator=(const big_integer<Bits2>& b) {
            m_negative = false;
            m_abs = b;
        }

        template<unsigned Bits2>
        inline constexpr signed_big_integer& operator=(
            const signed_big_integer<Bits2>& other) noexcept {
            m_negative = other.negative();
            m_abs = other.abs();
            return *this;
        }

        template<typename T,
                 std::enable_if_t<std::is_integral_v<T> && std::is_signed_v<T>, int> = 0>
        inline constexpr signed_big_integer& operator=(T val) noexcept {
            using std::abs;
            m_abs = abs(val);
            if (val < 0) {
                negate();
            }
            return *this;
        }

        template<typename T,
                 std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, int> = 0>
        inline constexpr signed_big_integer& operator=(T val) noexcept {
            m_negative = false;
            m_abs = val;
            return *this;
        }

        inline std::string str() const {
            return (negative() ? std::string("-") : std::string("")) + m_abs.str();
        }

        template<unsigned Bits2, std::enable_if_t<(Bits2 < Bits), int> = 0>
        inline constexpr signed_big_integer<Bits2> truncate() const noexcept {
            return {m_negative, m_abs.template truncate<Bits2>()};
        }

        // cast to integral types

        template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        explicit inline constexpr operator T() const {
            return multiplied_by_sign(static_cast<T>(abs()));
        }

        template<unsigned Bits2>
        explicit inline constexpr operator big_integer<Bits2>() const {
            NIL_CO3_MP_ASSERT(!this->negative());
            return m_abs;
        }

        // Utilities

        inline constexpr bool negative() const { return m_negative; }

        inline constexpr int sign() const noexcept {
            return negative() ? -1 : (is_zero(m_abs) ? 0 : 1);
        }

        inline constexpr unsigned_type abs() const { return m_abs; }

        inline constexpr void negate() {
            if (is_zero(m_abs)) {
                return;
            }
            m_negative = !m_negative;
        }

        // Comparision

        template<unsigned Bits>
        inline constexpr int compare(const signed_big_integer<Bits>& other) const noexcept {
            if (negative() && !other.negative()) {
                return -1;
            }
            if (!negative() && other.negative()) {
                return 1;
            }
            if (negative() && other.negative()) {
                return other.m_abs.compare(this->m_abs);
            }
            return this->m_abs.compare(other.m_abs);
        }

        // Arithmetic operations

        // Addition/subtraction

        static inline constexpr signed_big_integer<Bits + 1> add(
            const signed_big_integer& a, const signed_big_integer& b) noexcept {
            if (!a.negative() && !b.negative()) {
                return a.m_abs + b.m_abs;
            }
            if (!a.negative() && b.negative()) {
                if (a.m_abs >= b.m_abs) {
                    return a.m_abs - b.m_abs;
                }
                return -signed_big_integer<Bits + 1>(b.m_abs - a.m_abs);
            }
            if (a.negative() && !b.negative()) {
                return add(b, a);
            }
            return -signed_big_integer<Bits + 1>(a.m_abs + b.m_abs);
        }

        static inline constexpr signed_big_integer<Bits + 1> subtract(
            const signed_big_integer& a, const signed_big_integer& b) noexcept {
            return add(a, -b);
        }

        NIL_CO3_MP_FORCEINLINE constexpr void increment() noexcept {
            if (negative()) {
                --m_abs;
                normalize();
                return;
            }
            ++m_abs;
        }

        NIL_CO3_MP_FORCEINLINE constexpr void decrement() noexcept {
            if (negative()) {
                ++m_abs;
                return;
            }
            if (is_zero(m_abs)) {
                m_negative = true;
                ++m_abs;
                return;
            }
            --m_abs;
        }

        // Modulus

        static inline constexpr signed_big_integer modulus(const signed_big_integer& x,
                                                           const signed_big_integer& y) {
            return static_cast<signed_big_integer>(x -
                                                   static_cast<signed_big_integer>((x / y) * y));
        }

        // Divide

        static inline constexpr signed_big_integer divide(const signed_big_integer& x,
                                                          const signed_big_integer& y) {
            return x.m_abs / y.m_abs;
        }

        // Multiplication

        template<unsigned Bits2>
        static inline constexpr signed_big_integer<Bits + Bits2> multiply(
            const signed_big_integer& a, const signed_big_integer<Bits2>& b) noexcept {
            signed_big_integer<Bits + Bits2> result = a.m_abs * b.m_abs;
            if (a.sign() * b.sign() < 0) {
                result = -result;
            }
            return result;
        }

      private:
        inline constexpr void normalize() noexcept {
            if (is_zero(m_abs)) {
                m_negative = false;
            }
        }

        template<typename T>
        inline constexpr void multiply_by_sign(T& a) const {
            if (negative()) {
                a = -a;
            }
        }
        template<typename T>
        inline constexpr T multiplied_by_sign(const T& a) const {
            if (negative()) {
                return -a;
            }
            return a;
        }

        bool m_negative = false;
        big_integer<Bits> m_abs;
    };

    template<unsigned Bits>
    NIL_CO3_MP_FORCEINLINE constexpr bool is_zero(const signed_big_integer<Bits>& val) noexcept {
        return is_zero(val.abs());
    }

}  // namespace nil::crypto3::multiprecision

#include "nil/crypto3/multiprecision/big_integer/signed_big_integer_ops.hpp"  // IWYU pragma: keep
