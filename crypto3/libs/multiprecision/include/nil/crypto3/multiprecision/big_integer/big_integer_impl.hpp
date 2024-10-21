#pragma once

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"

#include <algorithm>
#include <array>
#include <climits>
#include <cstring>
#include <exception>
#include <ios>
#include <iostream>
#include <ranges>
#include <string>
#include <tuple>
#include <type_traits>

// TODO(ioxid): replace with custom code
#include <boost/multiprecision/cpp_int.hpp>

#include "nil/crypto3/multiprecision/big_integer/storage.hpp"

namespace nil::crypto3::multiprecision {
    template<unsigned Bits_>
    class big_integer {
      public:
        constexpr static unsigned Bits = Bits_;
        using self_type = big_integer<Bits>;

        using cpp_int_type = boost::multiprecision::number<boost::multiprecision::cpp_int_backend<
            Bits, Bits, boost::multiprecision::unsigned_magnitude,
            boost::multiprecision::unchecked>>;

        using limb_type = detail::limb_type;
        using double_limb_type = detail::double_limb_type;
        using signed_limb_type = detail::signed_limb_type;
        using signed_double_limb_type = detail::signed_double_limb_type;

        using unsigned_types = std::tuple<limb_type, double_limb_type>;
        using signed_types = std::tuple<signed_limb_type, signed_double_limb_type>;

        // Storage

        using limb_pointer = detail::limb_pointer;
        using const_limb_pointer = detail::const_limb_pointer;
        static constexpr unsigned limb_bits = detail::limb_bits;
        static constexpr unsigned max_limb_value = detail::max_limb_value;

        static constexpr unsigned internal_limb_count =
            (Bits / limb_bits) + (((Bits % limb_bits) != 0u) ? 1u : 0u);
        static constexpr limb_type upper_limb_mask =
            (Bits % limb_bits) ? (limb_type(1) << (Bits % limb_bits)) - 1 : (~limb_type(0u));

        //
        // Helper functions for getting at our internal data, and manipulating storage:
        //
        inline constexpr unsigned size() const noexcept {
            static_assert(internal_limb_count != 0, "No limbs in storage.");
            return internal_limb_count;
        }
        inline constexpr limb_pointer limbs() noexcept { return m_data.data(); }
        inline constexpr const_limb_pointer limbs() const noexcept { return m_data.data(); }
        inline constexpr bool sign() const noexcept { return false; }

        // Zeros out everything after limb[i], replaces resizing.
        inline constexpr void zero_after(std::size_t start_index) {
            auto pr = this->limbs();
            for (std::size_t i = start_index; i < this->size(); ++i) {
                pr[i] = 0;
            }
        }
        inline constexpr bool has_carry() const noexcept { return m_carry; }
        inline constexpr void set_carry(bool carry) noexcept { m_carry = carry; }

        inline constexpr void normalize() noexcept {
            limb_pointer p = limbs();
            p[internal_limb_count - 1] &= upper_limb_mask;
        }

        inline constexpr void do_swap(big_integer& other) noexcept {
            for (unsigned i = 0; i < internal_limb_count; ++i) {
                boost::multiprecision::std_constexpr::swap(m_data[i], other.m_data[i]);
            }
        }

        // Constructor

        inline constexpr big_integer() noexcept {}

        inline explicit constexpr big_integer(const cpp_int_type& other) {
            this->from_cpp_int(other);
        }

        // TODO(ioxid): forbid signed, implement comparison with signed instead
        template<class T,
                 std::enable_if_t<std::is_integral_v<T> /*&& std::is_unsigned_v<T>*/, int> = 0>
        inline constexpr big_integer(T val) noexcept {
            if (val < 0) {
                std::cerr << "big_integer: assignment from negative integer" << std::endl;
                std::terminate();
            }
            do_assign_integral(static_cast<std::make_unsigned_t<T>>(val));
        }

        // Copy construction

        inline constexpr big_integer(const big_integer& other) noexcept { do_assign(other); }
        template<unsigned Bits2>
        inline constexpr big_integer(const big_integer<Bits2>& other) noexcept {
            do_assign(other);
        }

        // Copy assignment

        inline constexpr auto& operator=(const big_integer& other) noexcept {
            do_assign(other);
            return *this;
        }
        template<unsigned Bits2>
        inline constexpr big_integer& operator=(const big_integer<Bits2>& other) noexcept {
            do_assign(other);
            return *this;
        }

        // Assignment from other types

        // TODO(ioxid): forbid signed, implement comparison with signed instead
        template<typename T>
        inline constexpr
            typename std::enable_if_t<std::is_integral_v<T> /*&& std::is_unsigned_v<T>*/,
                                      big_integer&>
            operator=(T val) noexcept {
            if (val < 0) {
                std::cerr << "big_integer: assignment from negative integer" << std::endl;
                std::terminate();
            }
            do_assign_integral(static_cast<std::make_unsigned_t<T>>(val));
            return *this;
        }

        inline constexpr auto& operator=(const char* s) {
            // TODO(ioxid): rewrite without cpp_int
            cpp_int_type value;
            value = s;
            this->from_cpp_int(value);
            return *this;
        }
        inline constexpr void swap(big_integer& other) noexcept { this->do_swap(other); }

        ~big_integer() = default;

        inline std::string str(std::streamsize digits = 0,
                               std::ios_base::fmtflags f = std::ios_base::fmtflags(0)) const {
            // TODO(ioxid): rewrite without cpp_int
            cpp_int_type value = to_cpp_int();
            return value.str(digits, f);
        }

        // cpp_int conversion

        inline constexpr void from_cpp_int(cpp_int_type cppint) {
            for (limb_type& limb : m_data) {
                limb = static_cast<limb_type>(cppint & static_cast<limb_type>(-1));
                cppint >>= limb_bits;
            }
        }

        // Converting to cpp_int. We need this for multiplication, division and string
        // conversions. Since these operations are rare, there's no reason to implement them for
        // big_integer, converting to cpp_int does not result to performance penalty.
        inline constexpr cpp_int_type to_cpp_int() const {
            cpp_int_type result;
            for (const limb_type limb : m_data | std::views::reverse) {
                result <<= limb_bits;
                result |= limb;
            }
            return result;
        }

        // cast to integral types

        template<typename T,
                 std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, int> = 0>
        explicit inline constexpr operator T() const {
            if constexpr (sizeof(T) <= sizeof(limb_type)) {
                return static_cast<T>(this->limbs()[0]);
            } else {
                constexpr std::size_t n = sizeof(T) / sizeof(limb_type);
                T result = 0;
                for (std::size_t i = 0; i < n; ++i) {
                    result <<= limb_bits;
                    result |= limbs()[n - i - 1];
                }
                return result;
            }
        }

      private:
        template<typename T,
                 std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, int> = 0>
        inline constexpr void do_assign_integral(T a) noexcept {
            if constexpr (sizeof(T) <= sizeof(limb_type)) {
                this->limbs()[0] = a;
                this->zero_after(1);
            } else {
                static_assert(sizeof(T) % sizeof(limb_type) == 0);
                constexpr std::size_t n = sizeof(T) / sizeof(limb_type);
                for (std::size_t i = 0; i < n; ++i) {
                    limbs()[i] = a & static_cast<T>(static_cast<limb_type>(-1));
                    a >>= limb_bits;
                }
                zero_after(n);
            }
            this->normalize();
        }

        template<unsigned Bits2>
        inline constexpr void do_assign(const big_integer<Bits2>& other) noexcept {
            unsigned count = (std::min)(other.size(), this->size());
            for (unsigned i = 0; i < count; ++i) {
                this->limbs()[i] = other.limbs()[i];
            }
            // Zero out everything after (std::min)(other.size(), this->size()), so if size of
            // other was less, we have 0s at the end.
            this->zero_after((std::min)(other.size(), this->size()));
            this->normalize();
        }

        // m_data[0] contains the lowest bits.
        std::array<limb_type, internal_limb_count> m_data{0};

        // This is a temporary value which is set when carry has happend during addition.
        // If this value is true, reduction by modulus must happen next.
        bool m_carry = false;
    };

    // Comparisions

    template<unsigned Bits>
    inline constexpr int compare(const big_integer<Bits>& a, const big_integer<Bits>& b) noexcept {
        auto pa = a.limbs();
        auto pb = b.limbs();
        for (int i = a.size() - 1; i >= 0; --i) {
            if (pa[i] != pb[i]) {
                return pa[i] > pb[i] ? 1 : -1;
            }
        }
        return 0;
    }
}  // namespace nil::crypto3::multiprecision
