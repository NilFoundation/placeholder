///////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#pragma once

#include <climits>
#include <limits>

#include "nil/crypto3/multiprecision/big_integer/big_integer_impl.hpp"

namespace nil::crypto3::multiprecision::detail {
    template<unsigned Bits>
    inline constexpr big_integer<Bits> get_min() {
        constexpr big_integer<Bits> val = 0u;
        return val;
    }

    template<unsigned Bits>
    inline constexpr nil::crypto3::multiprecision::big_integer<Bits> get_max() {
        constexpr auto val = ~big_integer<Bits>(0u);
        return val;
    }

    inline constexpr unsigned calc_digits10(unsigned d) {
        //
        // We need floor(log10(2) * (d-1)), see:
        // https://www.exploringbinary.com/number-of-digits-required-for-round-trip-conversions/
        // and references therein.
        //
        return static_cast<unsigned>(0.301029995663981195213738894724493026768189881462108541310 *
                                     static_cast<double>(d - 1u));
    }
}  // namespace nil::crypto3::multiprecision::detail

namespace std {
    template<unsigned Bits>
    class numeric_limits<nil::crypto3::multiprecision::big_integer<Bits>> {
        using number_type = nil::crypto3::multiprecision::big_integer<Bits>;

      public:
        static constexpr bool is_specialized = true;
        //
        // Largest and smallest numbers are bounded only by available memory, set
        // to zero:
        //
        static constexpr number_type(min)() {
            return nil::crypto3::multiprecision::detail::get_min<Bits>();
        }
        static constexpr number_type(max)() {
            return nil::crypto3::multiprecision::detail::get_max<Bits>();
        }
        static constexpr number_type lowest() { return (min)(); }
        static constexpr int digits = number_type::Bits;
        static constexpr int digits10 = nil::crypto3::multiprecision::detail::calc_digits10(digits);
        static constexpr int max_digits10 =
            nil::crypto3::multiprecision::detail::calc_digits10(digits);
        static constexpr bool is_signed = false;
        static constexpr bool is_integer = true;
        static constexpr bool is_exact = true;
        static constexpr int radix = 2;
        static constexpr number_type epsilon() { return 0; }
        static constexpr number_type round_error() { return 0; }
        static constexpr int min_exponent = 0;
        static constexpr int min_exponent10 = 0;
        static constexpr int max_exponent = 0;
        static constexpr int max_exponent10 = 0;
        static constexpr bool has_infinity = false;
        static constexpr bool has_quiet_NaN = false;
        static constexpr bool has_signaling_NaN = false;
        static constexpr float_denorm_style has_denorm = denorm_absent;
        static constexpr bool has_denorm_loss = false;
        static constexpr number_type infinity() { return 0; }
        static constexpr number_type quiet_NaN() { return 0; }
        static constexpr number_type signaling_NaN() { return 0; }
        static constexpr number_type denorm_min() { return 0; }
        static constexpr bool is_iec559 = false;
        static constexpr bool is_bounded = true;
        static constexpr bool is_modulo = true;
        static constexpr bool traps = false;
        static constexpr bool tinyness_before = false;
    };

}  // namespace std
