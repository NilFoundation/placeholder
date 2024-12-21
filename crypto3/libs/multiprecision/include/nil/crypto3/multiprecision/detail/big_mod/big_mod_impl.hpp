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

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_mod.hpp"

#include <climits>
#include <cstddef>
#include <functional>
#include <ios>
#include <limits>
#include <ostream>
#include <string>
#include <type_traits>

#include <boost/assert.hpp>

#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops.hpp"
#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops_storage.hpp"
#include "nil/crypto3/multiprecision/detail/big_mod/test_support.hpp"  // IWYU pragma: keep (for get_raw_base)
#include "nil/crypto3/multiprecision/detail/big_mod/type_traits.hpp"  // IWYU pragma: export
#include "nil/crypto3/multiprecision/detail/big_uint/big_uint_impl.hpp"
#include "nil/crypto3/multiprecision/detail/integer_ops_base.hpp"  // IWYU pragma: keep (used for is_zero)

namespace nil::crypto3::multiprecision {
    template<std::size_t Bits_, typename modular_ops_storage_t_>
    class big_mod_impl {
      public:
        static constexpr std::size_t Bits = Bits_;
        using big_uint_t = big_uint<Bits>;
        using modular_ops_storage_t = modular_ops_storage_t_;
        using modular_ops_t = typename modular_ops_storage_t::modular_ops_t;

        // Constructors

        // Only available in compile-time big_mod, initializes to zero
        constexpr big_mod_impl() : big_mod_impl(modular_ops_storage_t{}) {}

        // Only available in compile-time big_mod, initializes with the given base
        template<typename T, std::enable_if_t<detail::is_integral_v<T>, int> = 0>
        constexpr big_mod_impl(const T& b) : big_mod_impl(b, modular_ops_storage_t{}) {}

        // Only available in runtime big_mod, initializes with the given base and modulus
        template<typename T1, typename T2,
                 std::enable_if_t<detail::is_integral_v<T1> && detail::is_integral_v<T2>, int> = 0>
        constexpr big_mod_impl(const T1& b, const T2& m)
            : big_mod_impl(b, modular_ops_storage_t{m}) {}

        // For generic code

        // Avaiable both in compile-time and runtime big_mod, avoids costs of initializing
        // modular_ops_storage in runtime case
        constexpr big_mod_impl(const modular_ops_storage_t& modular_ops_storage)
            : m_modular_ops_storage(modular_ops_storage) {
            // NB: m_raw_base is initialized to zero, this is correct for Montgomery form too
        }

        // Avaiable both in compile-time and runtime big_mod, avoids costs of initializing
        // modular_ops_storage in runtime case
        template<typename T>
        constexpr big_mod_impl(const T& b, const modular_ops_storage_t& modular_ops_storage)
            : m_modular_ops_storage(modular_ops_storage) {
            if (!nil::crypto3::multiprecision::is_zero(b)) {
                init_raw_base(m_raw_base, b, ops());
            }
        }

        // Components

        constexpr big_uint_t base() const {
            big_uint_t result;
            ops().adjust_regular(result, raw_base());
            return result;
        }

        constexpr const big_uint_t& mod() const { return ops().mod(); }

        explicit constexpr operator big_uint_t() const { return base(); }

        explicit constexpr operator bool() const { return !is_zero(); }

        // Comparison

#define NIL_CO3_MP_BIG_MOD_COMPARISON_IMPL(OP_)                                      \
    friend constexpr bool operator OP_(const big_mod_impl& a,                        \
                                       const big_mod_impl& b) noexcept {             \
        BOOST_ASSERT(a.ops_storage().compare_eq(b.ops_storage()));                   \
        return a.raw_base() OP_ b.raw_base();                                        \
    }                                                                                \
                                                                                     \
    template<typename T, std::enable_if_t<detail::is_integral_v<T>, int> = 0>        \
    friend constexpr bool operator OP_(const big_mod_impl& a, const T& b) noexcept { \
        return a.base() OP_ b;                                                       \
    }                                                                                \
                                                                                     \
    template<typename T, std::enable_if_t<detail::is_integral_v<T>, int> = 0>        \
    friend constexpr bool operator OP_(const T& a, const big_mod_impl& b) noexcept { \
        return a OP_ b.base();                                                       \
    }

        NIL_CO3_MP_BIG_MOD_COMPARISON_IMPL(==)
        NIL_CO3_MP_BIG_MOD_COMPARISON_IMPL(!=)

#undef NIL_CO3_MP_BIG_MOD_COMPARISON_IMPL

        constexpr bool is_zero() const noexcept {
            // In barrett form raw_base is the same as base
            // In montgomery form raw_base is base multiplied by r, so it is zero iff base is
            return raw_base().is_zero();
        }

        // String conversion

        constexpr std::string str(std::ios_base::fmtflags flags = std::ios_base::hex |
                                                                  std::ios_base::showbase |
                                                                  std::ios_base::uppercase) const {
            return base().str(flags);
        }

        // Arithmetic operations

        constexpr void negate() { ops().negate(m_raw_base); }

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
            result.negate();
            return result;
        }

      private:
        template<typename S, std::enable_if_t<detail::is_integral_v<S>, int> = 0>
        static big_uint_t convert_to_raw_base(const S& s, const modular_ops_t& ops) {
            if (nil::crypto3::multiprecision::is_zero(s)) {
                return big_uint_t{};
            }
            big_uint_t result;
            init_raw_base(result, s, ops);
            return result;
        }

        static constexpr const big_uint_t& convert_to_raw_base(const big_mod_impl& s,
                                                               const modular_ops_t& /*ops*/) {
            return s.raw_base();
        }

      public:
#define NIL_CO3_MP_BIG_MOD_OPERATOR_IMPL(OP_, OP_ASSIGN_, METHOD_)                       \
    template<typename T,                                                                 \
             std::enable_if_t<                                                           \
                 std::is_same_v<big_mod_impl, T> || detail::is_integral_v<T>, int> = 0>  \
    friend constexpr auto operator OP_(const big_mod_impl& a, const T& b) noexcept {     \
        if constexpr (detail::is_big_mod_v<T>) {                                         \
            BOOST_ASSERT(a.ops_storage().compare_eq(b.ops_storage()));                   \
        }                                                                                \
        big_mod_impl result = a;                                                         \
        a.ops().METHOD_(result.m_raw_base, convert_to_raw_base(b, a.ops()));             \
        return result;                                                                   \
    }                                                                                    \
                                                                                         \
    template<typename T, std::enable_if_t<detail::is_integral_v<T>, int> = 0>            \
    friend constexpr auto operator OP_(const T& a, const big_mod_impl& b) noexcept {     \
        big_mod_impl result(b.ops_storage());                                            \
        result.m_raw_base = convert_to_raw_base(a, b.ops());                             \
        b.ops().METHOD_(result.m_raw_base, b.raw_base());                                \
        return result;                                                                   \
    }                                                                                    \
                                                                                         \
    template<typename T,                                                                 \
             std::enable_if_t<                                                           \
                 std::is_same_v<big_mod_impl, T> || detail::is_integral_v<T>, int> = 0>  \
    friend constexpr auto& operator OP_ASSIGN_(big_mod_impl & a, const T & b) noexcept { \
        if constexpr (detail::is_big_mod_v<T>) {                                         \
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
                 std::enable_if_t<detail::is_integral_v<T> && !std::numeric_limits<T>::is_signed,
                                  int> = 0>
        friend constexpr big_mod_impl pow_unsigned(big_mod_impl b, const T& e) {
            b.ops().pow(b.m_raw_base, b.raw_base(), e);
            return b;
        }

        // Hash

        friend constexpr std::size_t hash_value(const big_mod_impl& val) noexcept {
            return hash_value(val.raw_base());
            // mod() is ignored because we don't allow comparing numbers with different moduli
            // anyway
        }

        // IO

        friend std::ostream& operator<<(std::ostream& os, const big_mod_impl& value) {
            os << value.str(os.flags());
            return os;
        }

        // Accessing operations. Can be used to efficiently initialize a new big_mod_rt instance by
        // copying operations storage from an existing big_mod_rt instance.

        constexpr const auto& ops_storage() const { return m_modular_ops_storage; }

      private:
        constexpr const auto& ops() const { return m_modular_ops_storage.ops(); }
        constexpr const auto& raw_base() const { return m_raw_base; }

        // Data

        modular_ops_storage_t m_modular_ops_storage;
        big_uint_t m_raw_base;

        // Friends

        template<typename big_mod_t>
        friend constexpr const auto& detail::get_raw_base(const big_mod_t& a);
    };

    template<const auto& modulus, template<std::size_t> typename modular_ops_template>
    using big_mod_ct_impl =
        big_mod_impl<std::decay_t<decltype(modulus)>::Bits,
                     detail::modular_ops_storage_ct<modulus, modular_ops_template>>;

    template<std::size_t Bits, template<std::size_t> typename modular_ops_template>
    using big_mod_rt_impl =
        big_mod_impl<Bits, detail::modular_ops_storage_rt<Bits, modular_ops_template>>;

    // For generic code

    template<typename big_mod_t, std::enable_if_t<detail::is_big_mod_v<big_mod_t>, int> = 0>
    constexpr bool is_zero(const big_mod_t& a) {
        return a.is_zero();
    }

    // Actual big integer modular types

    // Montgomery modular big integer type with compile-time modulus. Modulus should be a static
    // big_uint constant.
    template<const auto& modulus>
    using montgomery_big_mod = big_mod_ct_impl<modulus, detail::montgomery_modular_ops>;

    // Montgomery modular big integer type with runtime modulus.
    template<std::size_t Bits>
    using montgomery_big_mod_rt = big_mod_rt_impl<Bits, detail::montgomery_modular_ops>;

    // Simple modular big integer type with compile-time modulus. Modulus should be a static
    // big_uint constant. Uses barret optimizations.
    template<const auto& modulus>
    using big_mod = big_mod_ct_impl<modulus, detail::barrett_modular_ops>;

    // Simple modular big integer type with runtime modulus. Uses barret optimizations.
    template<std::size_t Bits>
    using big_mod_rt = big_mod_rt_impl<Bits, detail::barrett_modular_ops>;

    // Modular big integer type with compile-time modulus, which automatically uses montomery form
    // whenever possible (i.e. for odd moduli). Modulus should be a static big_uint constant.
    template<const auto& modulus>
    using auto_big_mod = std::conditional_t<detail::check_montgomery_constraints(modulus),
                                            montgomery_big_mod<modulus>, big_mod<modulus>>;
}  // namespace nil::crypto3::multiprecision

// std::hash specializations

template<const auto& modulus_, template<std::size_t> typename modular_ops_template>
struct std::hash<nil::crypto3::multiprecision::big_mod_ct_impl<modulus_, modular_ops_template>> {
    std::size_t operator()(
        const nil::crypto3::multiprecision::big_mod_ct_impl<modulus_, modular_ops_template>& a)
        const noexcept {
        return boost::hash<
            nil::crypto3::multiprecision::big_mod_ct_impl<modulus_, modular_ops_template>>{}(a);
    }
};

template<std::size_t Bits, template<std::size_t> typename modular_ops_template>
struct std::hash<nil::crypto3::multiprecision::big_mod_rt_impl<Bits, modular_ops_template>> {
    std::size_t operator()(
        const nil::crypto3::multiprecision::big_mod_rt_impl<Bits, modular_ops_template>& a)
        const noexcept {
        return boost::hash<
            nil::crypto3::multiprecision::big_mod_rt_impl<Bits, modular_ops_template>>{}(a);
    }
};
