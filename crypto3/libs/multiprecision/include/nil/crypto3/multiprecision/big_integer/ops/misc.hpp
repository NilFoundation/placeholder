///////////////////////////////////////////////////////////////
//  Copyright 2012-2020 John Maddock.
//  Copyright 2020 Madhur Chauhan.
//  Distributed under the Boost Software License, Version 1.0.
//  (See accompanying file LICENSE_1_0.txt or copy at
//   https://www.boost.org/LICENSE_1_0.txt)
//
// Comparison operators for big_integer:
//
#pragma once

#include <boost/functional/hash.hpp>
#include <boost/functional/hash_fwd.hpp>
// #include <boost/multiprecision/detail/bitscan.hpp>  // lsb etc
#include <boost/multiprecision/detail/constexpr.hpp>
#include <cstddef>
#include <limits>
#include <type_traits>

#include "nil/crypto3/multiprecision/big_integer/big_integer_impl.hpp"
#include "nil/crypto3/multiprecision/big_integer/detail/config.hpp"
#include "nil/crypto3/multiprecision/big_integer/storage.hpp"

#ifdef BOOST_MSVC
#pragma warning(push)
#pragma warning(disable : 4702)
#pragma warning(disable : 4127)  // conditional expression is constant
#pragma warning( \
    disable : 4146)  // unary minus operator applied to unsigned type, result still unsigned
#endif

namespace nil::crypto3::multiprecision {
    // TODO refactor
    template<class R, unsigned Bits>
    inline constexpr
        typename std::enable_if<boost::multiprecision::detail::is_integral<R>::value, void>::type
        eval_convert_to(R *result, const big_integer<Bits> &backend) {
        if constexpr (boost::multiprecision::backends::numeric_limits_workaround<R>::digits <
                      big_integer<Bits>::limb_bits) {
            if (boost::multiprecision::detail::is_signed<R>::value &&
                boost::multiprecision::detail::is_integral<R>::value &&
                static_cast<limb_type>((std::numeric_limits<R>::max)()) <= backend.limbs()[0]) {
                *result = (boost::multiprecision::backends::numeric_limits_workaround<R>::max)();
                return;
            }
            *result = static_cast<R>(backend.limbs()[0]);
        } else
            *result = static_cast<R>(backend.limbs()[0]);

        unsigned shift = big_integer<Bits>::limb_bits;
        unsigned i = 1;
        if constexpr (boost::multiprecision::backends::numeric_limits_workaround<R>::digits >
                      big_integer<Bits>::limb_bits) {
            while (
                (i < backend.size()) &&
                (shift < static_cast<unsigned>(
                             boost::multiprecision::backends::numeric_limits_workaround<R>::digits -
                             big_integer<Bits>::limb_bits))) {
                *result += static_cast<R>(backend.limbs()[i]) << shift;
                shift += big_integer<Bits>::limb_bits;
                ++i;
            }
            //
            // We have one more limb to extract, but may not need all the Bits, so treat
            // this as a special case:
            //
            if (i < backend.size()) {
                const limb_type mask =
                    boost::multiprecision::backends::numeric_limits_workaround<R>::digits - shift ==
                            big_integer<Bits>::limb_bits
                        ? ~static_cast<limb_type>(0)
                        : (static_cast<limb_type>(1u)
                           << (boost::multiprecision::backends::numeric_limits_workaround<
                                   R>::digits -
                               shift)) -
                              1;
                *result += (static_cast<R>(backend.limbs()[i]) & mask) << shift;
                if ((static_cast<R>(backend.limbs()[i]) & static_cast<limb_type>(~mask)) ||
                    (i + 1 < backend.size())) {
                    // Overflow:
                    if (boost::multiprecision::detail::is_signed<R>::value) {
                        *result =
                            (boost::multiprecision::backends::numeric_limits_workaround<R>::max)();
                    }
                    return;
                }
            }
        } else if (backend.size() > 1) {
            // We will check for overflow here.
            for (std::size_t i = 1; i < backend.size(); ++i) {
                BOOST_ASSERT(backend.limbs()[i] == 0);
            }
        }
    }

    template<unsigned Bits>
    NIL_CO3_MP_FORCEINLINE constexpr bool eval_is_zero(const big_integer<Bits> &val) noexcept {
        // std::all_of is not constexpr, so writing manually.
        for (std::size_t i = 0; i < val.size(); ++i) {
            if (val.limbs()[i] != 0) {
                return false;
            }
        }
        return true;
    }

    //
    // Get the location of the least-significant-bit:
    //
    template<unsigned Bits>
    inline constexpr unsigned eval_lsb(const big_integer<Bits> &a) {
        //
        // Find the index of the least significant limb that is non-zero:
        //
        std::size_t index = 0;
        while (!a.limbs()[index] && (index < a.size())) {
            ++index;
        }
        //
        // Find the index of the least significant bit within that limb:
        //
        unsigned result = boost::multiprecision::detail::find_lsb(a.limbs()[index]);

        return result + index * big_integer<Bits>::limb_bits;
    }

    template<unsigned Bits>
    inline constexpr unsigned eval_msb(const big_integer<Bits> &a) {
        //
        // Find the index of the most significant bit that is non-zero:
        //
        for (std::size_t i = a.size() - 1; i > 0; --i) {
            if (a.limbs()[i] != 0) {
                return i * big_integer<Bits>::limb_bits +
                       boost::multiprecision::detail::find_msb(a.limbs()[i]);
            }
        }
        if (a.limbs()[0] == 0) {  // TODO here should assert/throw
            return 1024;          // Some big number to indicate that there is no bit 1
        }
        return boost::multiprecision::detail::find_msb(a.limbs()[0]);
    }

#ifdef BOOST_GCC
//
// We really shouldn't need to be disabling this warning, but it really does appear to be
// spurious.  The warning appears only when in release mode, and asserts are on.
//
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#endif

    template<unsigned Bits>
    inline constexpr bool eval_bit_test(const big_integer<Bits> &val, std::size_t index) noexcept {
        unsigned offset = index / big_integer<Bits>::limb_bits;
        unsigned shift = index % big_integer<Bits>::limb_bits;
        limb_type mask = limb_type(1u) << shift;
        if (offset >= val.size()) {
            return false;
        }
        return static_cast<bool>(val.limbs()[offset] & mask);
    }

#ifdef BOOST_GCC
#pragma GCC diagnostic pop
#endif

    template<unsigned Bits>
    inline constexpr void eval_bit_set(big_integer<Bits> &val, std::size_t index) {
        unsigned offset = index / big_integer<Bits>::limb_bits;
        unsigned shift = index % big_integer<Bits>::limb_bits;
        limb_type mask = limb_type(1u) << shift;
        if (offset >= val.size()) {
            return;  // fixed precision overflow
        }
        val.limbs()[offset] |= mask;
    }

    template<unsigned Bits>
    inline constexpr void eval_bit_unset(big_integer<Bits> &val, std::size_t index) noexcept {
        unsigned offset = index / big_integer<Bits>::limb_bits;
        unsigned shift = index % big_integer<Bits>::limb_bits;
        limb_type mask = limb_type(1u) << shift;
        if (offset >= val.size()) {
            return;
        }
        val.limbs()[offset] &= ~mask;
        val.normalize();
    }

    template<unsigned Bits>
    inline constexpr void eval_bit_flip(big_integer<Bits> &val, std::size_t index) {
        unsigned offset = index / big_integer<Bits>::limb_bits;
        unsigned shift = index % big_integer<Bits>::limb_bits;
        limb_type mask = limb_type(1u) << shift;
        if (offset >= val.size()) {
            return;  // fixed precision overflow
        }
        val.limbs()[offset] ^= mask;
        val.normalize();
    }

    // Since we don't have signed_type in big_integer, we need to override this
    // function.
    template<unsigned Bits, class Integer>
    inline constexpr
        typename std::enable_if<boost::multiprecision::detail::is_unsigned<Integer>::value,
                                Integer>::type
        eval_integer_modulus(const big_integer<Bits> &a, Integer mod) {
        if constexpr (sizeof(Integer) <= sizeof(limb_type)) {
            if (mod <= (std::numeric_limits<limb_type>::max)()) {
                const int n = a.size();
                const double_limb_type two_n_mod =
                    static_cast<limb_type>(1u) + (~static_cast<limb_type>(0u) - mod) % mod;
                limb_type res = a.limbs()[n - 1] % mod;

                for (int i = n - 2; i >= 0; --i) {
                    res = static_cast<limb_type>((res * two_n_mod + a.limbs()[i]) % mod);
                }
                return res;
            }
            return boost::multiprecision::default_ops::eval_integer_modulus(a, mod);
        } else {
            return boost::multiprecision::default_ops::eval_integer_modulus(a, mod);
        }
    }

    template<unsigned Bits, class Integer>
    NIL_CO3_MP_FORCEINLINE constexpr
        typename std::enable_if<boost::multiprecision::detail::is_signed<Integer>::value &&
                                    boost::multiprecision::detail::is_integral<Integer>::value,
                                Integer>::type
        eval_integer_modulus(const big_integer<Bits> &x, Integer val) {
        return eval_integer_modulus(x, boost::multiprecision::detail::unsigned_abs(val));
    }

    template<unsigned Bits>
    inline constexpr std::size_t hash_value(const big_integer<Bits> &val) noexcept {
        std::size_t result = 0;
        for (unsigned i = 0; i < val.size(); ++i) {
            boost::hash_combine(result, val.limbs()[i]);
        }
        return result;
    }

#ifdef BOOST_MSVC
#pragma warning(pop)
#endif

}  // namespace nil::crypto3::multiprecision

// TODO
// namespace detail {

//     // We need to specialize this class, because big_integer does not have
//     // signed_types. All we have changed here is Backend::signed_types ->
//     // Backend::unsigned_types, this will work for our use cases.
//     template<class Val, unsigned Bits>
//     struct canonical_imp<Val, big_integer<Bits>, std::integral_constant<int, 0>> {
//         static constexpr int index =
//             find_index_of_large_enough_type<typename big_integer<Bits>::unsigned_types, 0,
//                                             bits_of<Val>::value>::value;
//         using type = typename dereference_tuple<index, typename
//         big_integer<Bits>::unsigned_types,
//                                                 Val>::type;
//     };

// }  // namespace detail
