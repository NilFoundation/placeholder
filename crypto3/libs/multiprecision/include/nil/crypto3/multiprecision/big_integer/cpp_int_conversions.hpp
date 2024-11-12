#pragma once

#include <boost/multiprecision/cpp_int.hpp>
#include <cstddef>
#include <ranges>

#include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"
#include "nil/crypto3/multiprecision/big_integer/signed_big_integer.hpp"

// Converting to and from cpp_int. Should be used only in tests.

namespace nil::crypto3::multiprecision {
    template<std::size_t Bits>
    using unsigned_cpp_int_type =
        boost::multiprecision::number<boost::multiprecision::cpp_int_backend<
            Bits, Bits, boost::multiprecision::unsigned_magnitude,
            boost::multiprecision::unchecked>>;
    template<std::size_t Bits>
    using signed_cpp_int_type =
        boost::multiprecision::number<boost::multiprecision::cpp_int_backend<
            Bits, Bits, boost::multiprecision::signed_magnitude, boost::multiprecision::unchecked>>;

    template<std::size_t Bits>
    inline constexpr unsigned_cpp_int_type<Bits> to_cpp_int(const big_integer<Bits>& a) {
        unsigned_cpp_int_type<Bits> result;
        for (const limb_type limb : a.limbs_array() | std::views::reverse) {
            result <<= limb_bits;
            result |= limb;
        }
        return result;
    }

    template<std::size_t Bits>
    inline constexpr big_integer<Bits> to_big_integer(unsigned_cpp_int_type<Bits> cppint) {
        big_integer<Bits> result;
        for (limb_type& limb : result.limbs_array()) {
            limb = static_cast<detail::limb_type>(cppint & static_cast<detail::limb_type>(-1));
            cppint >>= limb_bits;
        }
        return result;
    }

    template<std::size_t Bits>
    inline constexpr signed_cpp_int_type<Bits> to_cpp_int(const signed_big_integer<Bits>& a) {
        signed_cpp_int_type<Bits> result = to_cpp_int(a.abs());
        if (a.sign() < 0) {
            result = -result;
        }
        return result;
    }

    template<std::size_t Bits>
    inline constexpr signed_big_integer<Bits> to_signed_big_integer(
        const signed_cpp_int_type<Bits>& cppint) {
        signed_big_integer<Bits> result = to_big_integer(abs(cppint));
        if (cppint.sign() < 0) {
            result = -result;
        }
        return result;
    }
}  // namespace nil::crypto3::multiprecision::detail
