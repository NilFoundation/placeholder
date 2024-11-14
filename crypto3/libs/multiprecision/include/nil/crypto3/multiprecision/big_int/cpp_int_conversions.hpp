#pragma once

#include <boost/multiprecision/cpp_int.hpp>
#include <cstddef>
#include <ranges>

#include "nil/crypto3/multiprecision/big_int/big_int.hpp"
#include "nil/crypto3/multiprecision/big_int/big_uint.hpp"

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
    inline constexpr unsigned_cpp_int_type<Bits> to_cpp_int(const big_uint<Bits>& a) {
        unsigned_cpp_int_type<Bits> result;
        for (const auto limb : a.limbs_array() | std::views::reverse) {
            result <<= detail::limb_bits;
            result |= limb;
        }
        return result;
    }

    template<std::size_t Bits>
    inline constexpr big_uint<Bits> to_big_uint(unsigned_cpp_int_type<Bits> cppint) {
        big_uint<Bits> result;
        for (auto& limb : result.limbs_array()) {
            limb = static_cast<detail::limb_type>(cppint & static_cast<detail::limb_type>(-1));
            cppint >>= detail::limb_bits;
        }
        return result;
    }

    template<std::size_t Bits>
    inline constexpr signed_cpp_int_type<Bits> to_cpp_int(const big_int<Bits>& a) {
        signed_cpp_int_type<Bits> result = to_cpp_int(a.abs());
        if (a.sign() < 0) {
            result = -result;
        }
        return result;
    }

    template<std::size_t Bits>
    inline constexpr big_int<Bits> to_big_int(const signed_cpp_int_type<Bits>& cppint) {
        big_int<Bits> result = to_big_uint(abs(cppint));
        if (cppint.sign() < 0) {
            result = -result;
        }
        return result;
    }
}  // namespace nil::crypto3::multiprecision
