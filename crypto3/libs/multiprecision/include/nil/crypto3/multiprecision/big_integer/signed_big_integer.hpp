#pragma once

// IWYU pragma: private; include "nil/crypto3/multiprecision/signed_big_integer/signed_big_integer.hpp"

#include <climits>
#include <cstring>
#include <ios>
#include <iostream>
#include <string>
#include <type_traits>

// TODO(ioxid): replace with custom code
#include <boost/multiprecision/cpp_int.hpp>
#include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"

namespace nil::crypto3::multiprecision {
    template<unsigned Bits_>
    class signed_big_integer {
      public:
        constexpr static unsigned Bits = Bits_;
        using self_type = signed_big_integer<Bits>;

        using unsigned_type = big_integer<Bits>;

        using cpp_int_type = boost::multiprecision::number<boost::multiprecision::cpp_int_backend<
            Bits, Bits, boost::multiprecision::signed_magnitude, boost::multiprecision::unchecked>>;

        // Constructor

        inline constexpr signed_big_integer() noexcept {}

        inline constexpr signed_big_integer(const big_integer<Bits> b) noexcept : m_unsigned(b) {}

        inline explicit constexpr signed_big_integer(const cpp_int_type& other) {
            this->from_cpp_int(other);
        }

        template<class T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        inline constexpr signed_big_integer(T val) noexcept : m_unsigned(abs(val)) {
            // for ADL
            using std::abs;

            if (val < 0) {
                negate();
            }
        }

        // Copy construction

        template<unsigned Bits2>
        inline constexpr signed_big_integer(const signed_big_integer<Bits2>& other) noexcept {
            do_assign(other);
        }

        // Copy assignment

        template<unsigned Bits2>
        inline constexpr signed_big_integer& operator=(
            const signed_big_integer<Bits2>& other) noexcept {
            do_assign(other);
            return *this;
        }

        // Assignment from other types

        template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        inline constexpr signed_big_integer& operator=(T val) noexcept {
            using std::abs;
            m_unsigned = abs(val);
            if (val < 0) {
                negate();
            }
            return *this;
        }

        inline std::string str(std::streamsize digits = 0,
                               std::ios_base::fmtflags f = std::ios_base::fmtflags(0)) const {
            return (negative() ? std::string("-") : std::string("")) + m_unsigned.str(digits, f);
        }

        // cpp_int conversion

        inline constexpr void from_cpp_int(cpp_int_type cppint) {
            m_unsigned.from_cpp_int(abs(cppint));
            if (cppint.sign() < 0) {
                negate();
            }
        }

        inline constexpr cpp_int_type to_cpp_int() const {
            return multiplied_by_sign(static_cast<cpp_int_type>(m_unsigned.to_cpp_int()));
        }

        // cast to integral types

        template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        explicit inline constexpr operator T() const {
            return multiplied_by_sign(static_cast<T>(sans_sign()));
        }

        inline constexpr bool negative() const { return bit_test(m_unsigned, Bits - 1); }

        inline constexpr int sign() const noexcept {
            return negative() ? -1 : (is_zero(m_unsigned) ? 0 : 1);
        }

        explicit inline constexpr operator unsigned_type() const { return m_unsigned; }

        inline constexpr big_integer<Bits - 1> sans_sign() const {
            auto copy = m_unsigned;
            bit_unset(copy, Bits - 1);
            return copy;
        }

        inline constexpr void negate() {
            if (is_zero(m_unsigned)) {
                return;
            }
            m_unsigned = ~unsigned_type(0u) - (m_unsigned - 1u);
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
                return other.m_unsigned.compare(this->m_unsigned);
            }
            return this->m_unsigned.compare(other.m_unsigned);
        }

      private:
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

        signed_big_integer<Bits> m_unsigned;
    };

}  // namespace nil::crypto3::multiprecision
