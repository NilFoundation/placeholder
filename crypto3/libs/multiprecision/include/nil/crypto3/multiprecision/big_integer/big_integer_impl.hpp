#pragma once

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"

#include <algorithm>
#include <array>
#include <climits>
#include <cstring>
#include <exception>
#include <ios>
#include <iostream>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>

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

        using unsigned_types = std::tuple<limb_type, double_limb_type>;
        using signed_types = std::tuple<signed_limb_type, signed_double_limb_type>;

        // Storage

        using limb_type = limb_type;
        using double_limb_type = double_limb_type;
        using limb_pointer = limb_type*;
        using const_limb_pointer = const limb_type*;

        static constexpr unsigned limb_bits = sizeof(limb_type) * CHAR_BIT;
        static constexpr limb_type max_limb_value = ~static_cast<limb_type>(0u);
        static constexpr unsigned internal_limb_count =
            (Bits / limb_bits) + (((Bits % limb_bits) != 0u) ? 1 : 0);
        static constexpr limb_type upper_limb_mask =
            (Bits % limb_bits) ? (limb_type(1) << (Bits % limb_bits)) - 1 : (~limb_type(0));

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
        template<class UI, std::enable_if_t<std::is_integral_v<UI> /*&& std::is_unsigned_v<UI>*/,
                                            bool> = true>
        inline constexpr big_integer(UI val) noexcept {
            if (val < 0) {
                std::cerr << "big_integer: assignment from negative integer" << std::endl;
                std::terminate();
            }
            // TODO(ioxid): support assignment from uint64_t and uint128_t
            do_assign_integral(static_cast<limb_type>(val));
        }

        // Move constructors

        inline constexpr big_integer(big_integer&& other) noexcept { do_assign(other); }

        template<unsigned Bits2>
        inline constexpr big_integer(big_integer<Bits2>&& other) noexcept {
            do_assign(other);
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

        // Move assignment

        inline constexpr auto& operator=(big_integer&& other) noexcept {
            do_assign(other);
            return *this;
        }
        template<unsigned Bits2>
        inline constexpr big_integer& operator=(big_integer<Bits2>&& other) noexcept {
            do_assign(other);
            return *this;
        }

        // Assignment from other types

        // TODO(ioxid): forbid signed, implement comparison with signed instead
        template<class UI>
        inline constexpr
            typename std::enable_if_t<std::is_integral_v<UI> /*&& std::is_unsigned_v<UI>*/,
                                      big_integer&>
            operator=(UI val) noexcept {
            if (val < 0) {
                std::cerr << "big_integer: assignment from negative integer" << std::endl;
                std::terminate();
            }
            do_assign_integral(val);
            return *this;
        }

        inline constexpr auto& operator=(const char* s) {
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

        inline constexpr void from_cpp_int(const cpp_int_type& other) {
            // Here we need other.size(), not this->size(), because cpp_int may not use all the
            // limbs it has, but we will.
            for (unsigned i = 0; i < other.backend().size(); ++i) {
                this->limbs()[i] = other.backend().limbs()[i];
            }
            // Zero out the rest.
            for (unsigned i = other.backend().size(); i < this->size(); ++i) {
                this->limbs()[i] = 0;
            }
        }

        // Converting to cpp_int. We need this for multiplication, division and string
        // conversions. Since these operations are rare, there's no reason to implement then for
        // big_integer, converting to cpp_int does not result to performance penalty.
        inline constexpr cpp_int_type to_cpp_int() const {
            cpp_int_type result;
            // TODO(ioxid): not constexpr?
            // result.backend().resize(this->size(), this->size());
            // for (unsigned i = 0; i < this->size(); ++i) {
            //     result.backend().limbs()[i] = this->limbs()[i];
            // }
            // result.backend().normalize();
            return std::move(result);
        }

        // cast to integral types

        template<typename T, std::enable_if_t<std::is_integral_v<T>, bool> = true>
        explicit inline constexpr operator T() const {
            return static_cast<T>(this->limbs()[0]);
        }

      private:
        inline constexpr void do_assign_integral(limb_type i) noexcept {
            // TODO(ioxid): support assignment from uint64_t and uint128_t
            *this->limbs() = i;
            this->zero_after(1);
            this->normalize();
        }

        inline constexpr void do_assign_integral(double_limb_type i) noexcept {
            // TODO(ioxid): support assignment from uint128_t
            static_assert(sizeof(i) == 2 * sizeof(limb_type), "Failed integer size check");
            auto p = this->limbs();
            *p = static_cast<limb_type>(i);
            if (this->size() > 1) {
                p[1] = static_cast<limb_type>(i >> limb_bits);
                this->zero_after(2);
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
