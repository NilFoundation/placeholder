//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <climits>
#include <cstddef>
#include <functional>
#include <ios>
#include <limits>
#include <ostream>
#include <string>
#include <type_traits>

#include <boost/assert.hpp>
#include <boost/functional/hash.hpp>

#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops/babybear.hpp"  // IWYU pragma: export
#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops/barrett.hpp"
#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops/goldilocks.hpp"  // IWYU pragma: export
#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops/koalabear.hpp"  // IWYU pragma: export
#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops/mersenne31.hpp"  // IWYU pragma: export
#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops/montgomery.hpp"
#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops_storage.hpp"
#include "nil/crypto3/multiprecision/detail/integer_ops_base.hpp"  // IWYU pragma: keep (used for is_zero)
#include "nil/crypto3/multiprecision/type_traits.hpp"

#include "nil/crypto3/multiprecision/detail/big_mod/test_support.hpp"  // IWYU pragma: keep (for get_raw_base)

namespace nil::crypto3::multiprecision {
    template<typename modular_ops_storage_t_>
    class big_mod_impl {
      public:
        using modular_ops_storage_t = modular_ops_storage_t_;
        using modular_ops_t = typename modular_ops_storage_t::modular_ops_t;
        using base_type = typename modular_ops_t::base_type;
        static constexpr std::size_t Bits = modular_ops_t::Bits;

        // Constructors

        // Only available in compile-time big_mod, initializes to zero
        constexpr big_mod_impl() : big_mod_impl(modular_ops_storage_t{}) {}

        // Only available in compile-time big_mod, initializes with the given base
        template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>
        constexpr big_mod_impl(const T& b) : big_mod_impl(b, modular_ops_storage_t{}) {}

        // Only available in runtime big_mod, initializes with the given base and modulus
        template<typename T1, typename T2,
                 std::enable_if_t<is_integral_v<T1> && is_integral_v<T2>, int> = 0>
        constexpr big_mod_impl(const T1& b, const T2& m)
            : big_mod_impl(b, modular_ops_storage_t{m}) {}

        // For generic code

        // Avaiable both in compile-time and runtime big_mod, avoids costs of initializing
        // modular_ops_storage in runtime case
        constexpr big_mod_impl(const modular_ops_storage_t& modular_ops_storage)
            : m_modular_ops_storage(modular_ops_storage) {
            // NB: m_raw_base is initialized to zero, this is correct for Montgomery form
            // too
        }

        // Avaiable both in compile-time and runtime big_mod, avoids costs of initializing
        // modular_ops_storage in runtime case
        template<typename T>
        constexpr big_mod_impl(const T& b,
                               const modular_ops_storage_t& modular_ops_storage)
            : m_modular_ops_storage(modular_ops_storage) {
            if (!nil::crypto3::multiprecision::is_zero(b)) {
                init_raw_base(m_raw_base, b, ops());
            }
        }

        // Components

      private:
        constexpr base_type internal_base() const {
            base_type result;
            ops().adjust_regular(result, raw_base());
            return result;
        }

      public:
        constexpr auto to_integral() const { return big_uint<Bits>(internal_base()); }

        constexpr decltype(auto) mod() const {
            if constexpr (is_big_uint_v<base_type>) {
                return ops().mod();
            } else {
                return big_uint<Bits>(ops().mod());
            }
        }

        explicit constexpr operator auto() const { return to_integral(); }

        explicit constexpr operator bool() const { return !is_zero(); }

        // Comparison

#define NIL_CO3_MP_BIG_MOD_COMPARISON_IMPL(OP_)                                      \
    friend constexpr bool operator OP_(const big_mod_impl& a,                        \
                                       const big_mod_impl& b) noexcept {             \
        BOOST_ASSERT(a.ops_storage().compare_eq(b.ops_storage()));                   \
        return a.raw_base() OP_ b.raw_base();                                        \
    }                                                                                \
                                                                                     \
    template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>                \
    friend constexpr bool operator OP_(const big_mod_impl& a, const T& b) noexcept { \
        return a.internal_base() OP_ b;                                              \
    }                                                                                \
                                                                                     \
    template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>                \
    friend constexpr bool operator OP_(const T& a, const big_mod_impl& b) noexcept { \
        return a OP_ b.internal_base();                                              \
    }

        NIL_CO3_MP_BIG_MOD_COMPARISON_IMPL(==)
        NIL_CO3_MP_BIG_MOD_COMPARISON_IMPL(!=)

#undef NIL_CO3_MP_BIG_MOD_COMPARISON_IMPL

        constexpr bool is_zero() const noexcept {
            // In barrett form raw_base is the same as base
            // In montgomery form raw_base is base multiplied by r, so it is zero iff base
            // is
            return nil::crypto3::multiprecision::is_zero(raw_base());
        }

        // String conversion

        constexpr std::string str(
            std::ios_base::fmtflags flags = std::ios_base::hex | std::ios_base::showbase |
                                            std::ios_base::uppercase) const {
            // TODO(ioxid): optimize when base_type is not big_uint
            return to_integral().str(flags);
        }

        // Arithmetic operations

        constexpr void negate_inplace() { ops().negate_inplace(m_raw_base); }

        constexpr auto& operator++() noexcept {
            ops().increment(m_raw_base);
            return *this;
        }

        constexpr auto operator++(int) noexcept {
            auto copy = *this;
            ++*this;
            return copy;
        }

        constexpr auto operator+() const noexcept { return *this; }

        constexpr auto& operator--() noexcept {
            ops().decrement(m_raw_base);
            return *this;
        }

        constexpr auto operator--(int) noexcept {
            auto copy = *this;
            --*this;
            return copy;
        }

        constexpr auto operator-() const noexcept {
            auto result = *this;
            result.negate_inplace();
            return result;
        }

      private:
        template<typename S, std::enable_if_t<is_integral_v<S>, int> = 0>
        static constexpr base_type convert_to_raw_base(const S& s,
                                                       const modular_ops_t& ops) {
            if (nil::crypto3::multiprecision::is_zero(s)) {
                return base_type{};
            }
            base_type result;
            init_raw_base(result, s, ops);
            return result;
        }

        static constexpr const base_type& convert_to_raw_base(
            const big_mod_impl& s, const modular_ops_t& /*ops*/) {
            return s.raw_base();
        }

      public:
#define NIL_CO3_MP_BIG_MOD_OPERATOR_IMPL(OP_, OP_ASSIGN_, METHOD_)                       \
    template<                                                                            \
        typename T,                                                                      \
        std::enable_if_t<std::is_same_v<big_mod_impl, T> || is_integral_v<T>, int> = 0>  \
    friend constexpr auto operator OP_(const big_mod_impl& a, const T& b) noexcept {     \
        if constexpr (is_big_mod_v<T>) {                                                 \
            BOOST_ASSERT(a.ops_storage().compare_eq(b.ops_storage()));                   \
        }                                                                                \
        big_mod_impl result = a;                                                         \
        a.ops().METHOD_(result.m_raw_base, convert_to_raw_base(b, a.ops()));             \
        return result;                                                                   \
    }                                                                                    \
                                                                                         \
    template<typename T, std::enable_if_t<is_integral_v<T>, int> = 0>                    \
    friend constexpr auto operator OP_(const T& a, const big_mod_impl& b) noexcept {     \
        big_mod_impl result(b.ops_storage());                                            \
        result.m_raw_base = convert_to_raw_base(a, b.ops());                             \
        b.ops().METHOD_(result.m_raw_base, b.raw_base());                                \
        return result;                                                                   \
    }                                                                                    \
                                                                                         \
    template<                                                                            \
        typename T,                                                                      \
        std::enable_if_t<std::is_same_v<big_mod_impl, T> || is_integral_v<T>, int> = 0>  \
    friend constexpr auto& operator OP_ASSIGN_(big_mod_impl & a, const T & b) noexcept { \
        if constexpr (is_big_mod_v<T>) {                                                 \
            BOOST_ASSERT(a.ops_storage().compare_eq(b.ops_storage()));                   \
        }                                                                                \
        a.ops().METHOD_(a.m_raw_base, convert_to_raw_base(b, a.ops()));                  \
        return a;                                                                        \
    }

        NIL_CO3_MP_BIG_MOD_OPERATOR_IMPL(+, +=, add)
        NIL_CO3_MP_BIG_MOD_OPERATOR_IMPL(-, -=, sub)
        NIL_CO3_MP_BIG_MOD_OPERATOR_IMPL(*, *=, mul)

#undef NIL_CO3_MP_BIG_MOD_OPERATOR_IMPL

        template<typename T,
                 std::enable_if_t<is_integral_v<T> && !std::numeric_limits<T>::is_signed,
                                  int> = 0>
        friend constexpr big_mod_impl pow_unsigned(big_mod_impl b, const T& e) {
            detail::pow_unsigned(b.m_raw_base, b.raw_base(), e, b.ops());
            return b;
        }

        // Hash

        friend constexpr std::size_t hash_value(const big_mod_impl& value) noexcept {
            return boost::hash<base_type>{}(value.raw_base());
            // mod() is ignored because we don't allow comparing numbers with different
            // moduli anyway
        }

        // IO

        friend std::ostream& operator<<(std::ostream& os, const big_mod_impl& value) {
            os << value.str(os.flags());
            return os;
        }

        // Accessing operations. Can be used to efficiently initialize a new big_mod_rt
        // instance by copying operations storage from an existing big_mod_rt instance.

        constexpr const auto& ops_storage() const { return m_modular_ops_storage; }

      private:
        constexpr const auto& ops() const { return m_modular_ops_storage.ops(); }
        constexpr const auto& raw_base() const { return m_raw_base; }

        // Data

        base_type m_raw_base{};
        [[no_unique_address]] modular_ops_storage_t m_modular_ops_storage;

        // Friends

        template<typename big_mod_t>
        friend constexpr const auto& detail::get_raw_base(const big_mod_t& a);
    };

    template<const auto& Modulus, template<std::size_t> typename modular_ops_template>
    using big_mod_ct_impl = big_mod_impl<detail::modular_ops_storage_ct<
        Modulus, modular_ops_template<std::decay_t<decltype(Modulus)>::Bits>>>;

    template<std::size_t Bits, template<std::size_t> typename modular_ops_template>
    using big_mod_rt_impl =
        big_mod_impl<detail::modular_ops_storage_rt<modular_ops_template<Bits>>>;

    // For generic code

    template<typename big_mod_t, std::enable_if_t<is_big_mod_v<big_mod_t>, int> = 0>
    constexpr bool is_zero(const big_mod_t& a) {
        return a.is_zero();
    }

    // User-facing big integer modular types

    // Montgomery modular big integer type with compile-time modulus. Modulus should be a
    // static big_uint constant.
    template<const auto& Modulus>
    using montgomery_big_mod = big_mod_ct_impl<Modulus, detail::montgomery_modular_ops>;

    // Montgomery modular big integer type with runtime modulus.
    template<std::size_t Bits>
    using montgomery_big_mod_rt = big_mod_rt_impl<Bits, detail::montgomery_modular_ops>;

    // Simple modular big integer type with compile-time modulus. Modulus should be a
    // static big_uint constant. Uses barret optimizations.
    template<const auto& Modulus>
    using big_mod = big_mod_ct_impl<Modulus, detail::barrett_modular_ops>;

    // Simple modular big integer type with runtime modulus. Uses barret optimizations.
    template<std::size_t Bits>
    using big_mod_rt = big_mod_rt_impl<Bits, detail::barrett_modular_ops>;

    // Goldilocks modular type with optimizations
    using goldilocks_mod = big_mod_impl<detail::goldilocks_modular_ops_storage>;

    // Mersenne31 modular type, without optimizations for now
    using mersenne31_mod = big_mod_impl<detail::mersenne31_modular_ops_storage>;

    // KoalaBear modular type, without optimizations for now
    using koalabear_mod = big_mod_impl<detail::koalabear_modular_ops_storage>;

    // BabyBear modular type, without optimizations for now
    using babybear_mod = big_mod_impl<detail::babybear_modular_ops_storage>;

    // Modular big integer type with compile-time modulus, which automatically uses
    // montomery form whenever possible (i.e. for odd moduli). Modulus should be a static
    // big_uint constant.
    template<const auto& Modulus>
    using auto_big_mod = std::conditional_t<
        Modulus == goldilocks_modulus, goldilocks_mod,
        std::conditional_t<
            Modulus == mersenne31_modulus, mersenne31_mod,
            std::conditional_t<
                Modulus == koalabear_modulus, koalabear_mod,
                std::conditional_t<
                    Modulus == babybear_modulus, babybear_mod,
                    std::conditional_t<detail::modulus_supports_montgomery(Modulus),
                                       montgomery_big_mod<Modulus>, big_mod<Modulus>>>>>>;
}  // namespace nil::crypto3::multiprecision

// std::hash specialization

template<typename modular_ops_storage_t>
struct std::hash<nil::crypto3::multiprecision::big_mod_impl<modular_ops_storage_t>> {
    std::size_t operator()(
        const nil::crypto3::multiprecision::big_mod_impl<modular_ops_storage_t>& a)
        const noexcept {
        return boost::hash<
            nil::crypto3::multiprecision::big_mod_impl<modular_ops_storage_t>>{}(a);
    }
};
