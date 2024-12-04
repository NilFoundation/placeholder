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

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_int/modular/big_mod.hpp"

#include <climits>
#include <cstddef>
#include <functional>
#include <ios>
#include <ostream>
#include <string>
#include <type_traits>

#include "nil/crypto3/multiprecision/big_int/big_uint_impl.hpp"
#include "nil/crypto3/multiprecision/big_int/detail/assert.hpp"
#include "nil/crypto3/multiprecision/big_int/modular/modular_ops.hpp"
#include "nil/crypto3/multiprecision/big_int/modular/modular_ops_storage.hpp"

namespace nil::crypto3::multiprecision {
    namespace detail {
        template<std::size_t Bits_, typename modular_ops_storage_t_>
        class big_mod_impl {
          public:
            static constexpr std::size_t Bits = Bits_;
            using big_uint_t = big_uint<Bits>;
            using modular_ops_storage_t = modular_ops_storage_t_;
            using modular_ops_t = typename modular_ops_storage_t::modular_ops_t;

            // Constructors

          protected:
            template<typename T>
            constexpr big_mod_impl(const T& b, const modular_ops_storage_t& modular_ops_storage)
                : m_modular_ops_storage(modular_ops_storage) {
                init_raw_base(m_raw_base, b, ops());
            }

          public:
            // Components

            constexpr big_uint_t base() const {
                big_uint_t result;
                ops().adjust_regular(result, m_raw_base);
                return result;
            }

            constexpr const big_uint_t& mod() const { return ops().mod(); }

            explicit constexpr operator big_uint_t() const { return base(); }

            // String conversion

            constexpr std::string str(
                std::ios_base::fmtflags flags = std::ios_base::hex | std::ios_base::showbase |
                                                std::ios_base::uppercase) const {
                return base().str(flags);
            }

            // Mathemetical operations

            constexpr void negate() { ops().negate(m_raw_base); }

            // Misc ops

            constexpr bool is_zero() const noexcept {
                // In barrett form raw_base is the same as base
                // In montgomery form raw_base is base multiplied by r, so it is zero iff base is
                return raw_base().is_zero();
            }

            // Accessing raw base value. Should only be used internally by multiprecision library.
            constexpr auto& raw_base() { return m_raw_base; }
            constexpr const auto& raw_base() const { return m_raw_base; }

            constexpr const auto& ops_storage() const { return m_modular_ops_storage; }
            constexpr const auto& ops() const { return m_modular_ops_storage.ops(); }

          protected:
            modular_ops_storage_t m_modular_ops_storage;
            big_uint_t m_raw_base;
        };
    }  // namespace detail

    template<const auto& modulus, template<std::size_t> typename modular_ops_template>
    struct big_mod_ct_impl : public detail::big_mod_impl<
                                 std::decay_t<decltype(modulus)>::Bits,
                                 detail::modular_ops_storage_ct<modulus, modular_ops_template>> {
        using base_type =
            detail::big_mod_impl<std::decay_t<decltype(modulus)>::Bits,
                                 detail::modular_ops_storage_ct<modulus, modular_ops_template>>;

        using typename base_type::big_uint_t;
        using typename base_type::modular_ops_storage_t;
        using typename base_type::modular_ops_t;

        constexpr big_mod_ct_impl() : base_type(big_uint_t{}, {}) {}

        template<typename T, std::enable_if_t<detail::is_integral_v<T>, int> = 0>
        constexpr big_mod_ct_impl(const T& b) : base_type(b, {}) {}

        // For generic code
        template<typename T, std::enable_if_t<detail::is_integral_v<T>, int> = 0>
        constexpr big_mod_ct_impl(const T& b, const modular_ops_storage_t& ops_storage)
            : base_type(b, ops_storage) {}
    };

    template<std::size_t Bits, template<std::size_t> typename modular_ops_template>
    struct big_mod_rt_impl
        : public detail::big_mod_impl<Bits,
                                      detail::modular_ops_storage_rt<Bits, modular_ops_template>> {
        using base_type =
            detail::big_mod_impl<Bits, detail::modular_ops_storage_rt<Bits, modular_ops_template>>;

        using typename base_type::big_uint_t;
        using typename base_type::modular_ops_storage_t;
        using typename base_type::modular_ops_t;

        template<typename T1, typename T2,
                 std::enable_if_t<detail::is_integral_v<T1> && detail::is_integral_v<T1>, int> = 0>
        constexpr big_mod_rt_impl(const T1& b, const T2& m) : base_type(b, m) {}

        // For generic code
        template<typename T, std::enable_if_t<detail::is_integral_v<T>, int> = 0>
        constexpr big_mod_rt_impl(const T& b, const modular_ops_storage_t& ops_storage)
            : base_type(b, ops_storage) {}
    };

    namespace detail {
        template<typename T>
        constexpr bool is_big_mod_v = false;

        template<const auto& modulus, template<std::size_t> typename modular_ops_storage_t>
        constexpr bool is_big_mod_v<big_mod_ct_impl<modulus, modular_ops_storage_t>> = true;

        template<std::size_t Bits, template<std::size_t> typename modular_ops_storage_t>
        constexpr bool is_big_mod_v<big_mod_rt_impl<Bits, modular_ops_storage_t>> = true;

        template<typename T>
        constexpr bool is_modular_integral_v =
            std::is_integral_v<T> || detail::is_big_uint_v<T> || is_big_mod_v<T>;

        template<typename T, std::enable_if_t<detail::is_big_mod_v<T>, int> = 0>
        constexpr std::size_t get_bits() {
            return T::Bits;
        }

        template<typename S, typename modular_ops_t,
                 std::enable_if_t<detail::is_integral_v<S>, int> = 0>
        typename modular_ops_t::big_uint_t convert_to_raw_base(const S& s,
                                                               const modular_ops_t& ops) {
            typename modular_ops_t::big_uint_t result;
            init_raw_base(result, s, ops);
            return result;
        }

        template<typename T, std::enable_if_t<detail::is_big_mod_v<T>, int> = 0>
        constexpr typename T::big_uint_t convert_to_raw_base(
            const T& s, const typename T::modular_ops_t& /*ops*/) {
            return s.raw_base();
        }

        template<typename T1, typename T2>
        constexpr void assert_equal_ops_in_operands(const T1& a, const T2& b) {
            if constexpr (detail::is_big_mod_v<T1> && detail::is_big_mod_v<T2>) {
                NIL_CO3_MP_ASSERT(a.ops().compare_eq(b.ops()));
            }
        }

        template<typename T1, typename T2>
        constexpr const auto& get_ops_storage_from_operands(const T1& a, const T2& b) {
            assert_equal_ops_in_operands(a, b);
            if constexpr (detail::is_big_mod_v<T1>) {
                return a.ops_storage();
            } else if constexpr (detail::is_big_mod_v<T2>) {
                return b.ops_storage();
            } else {
                static_assert(false, "none of the types are big_mod");
            }
        }

        template<typename T1, typename T2>
        constexpr bool are_valid_operand_types() {
            if (detail::is_big_mod_v<T1> && detail::is_big_mod_v<T2>) {
                return std::is_same_v<T1, T2>;
            }
            return detail::is_modular_integral_v<T1> && detail::is_modular_integral_v<T2> &&
                   (detail::is_big_mod_v<T1> || detail::is_big_mod_v<T2>);
        }
    }  // namespace detail

    // Comparison

#define NIL_CO3_MP_MODULAR_BIG_UINT_COMPARISON_IMPL(OP_)                           \
    template<typename T1, typename T2,                                             \
             std::enable_if_t<detail::are_valid_operand_types<T1, T2>(), int> = 0> \
    constexpr bool operator OP_(const T1& a, const T2& b) noexcept {               \
        const auto& ops_storage = detail::get_ops_storage_from_operands(a, b);     \
        return detail::convert_to_raw_base(a, ops_storage.ops())                   \
            OP_ detail::convert_to_raw_base(b, ops_storage.ops());                 \
    }

    NIL_CO3_MP_MODULAR_BIG_UINT_COMPARISON_IMPL(==)
    NIL_CO3_MP_MODULAR_BIG_UINT_COMPARISON_IMPL(!=)

#undef NIL_CO3_MP_MODULAR_BIG_UINT_COMPARISON_IMPL

    // Arithmetic operations

#define NIL_CO3_MP_MODULAR_BIG_UINT_OPERATOR_IMPL(OP_, OP_ASSIGN_, METHOD_)                   \
    template<typename T1, typename T2,                                                        \
             std::enable_if_t<detail::are_valid_operand_types<T1, T2>(), int> = 0,            \
             typename big_mod_t = std::conditional_t<detail::is_big_mod_v<T1>, T1, T2>>       \
    constexpr auto operator OP_(const T1& a, const T2& b) noexcept {                          \
        const auto& ops_storage = detail::get_ops_storage_from_operands(a, b);                \
        big_mod_t result(0u, ops_storage);                                                    \
        result.raw_base() = detail::convert_to_raw_base(a, ops_storage.ops());                \
        ops_storage.ops().METHOD_(result.raw_base(),                                          \
                                  detail::convert_to_raw_base(b, ops_storage.ops()));         \
        return result;                                                                        \
    }                                                                                         \
    template<typename big_mod_t, typename T,                                                  \
             std::enable_if_t<detail::is_big_mod_v<big_mod_t> &&                              \
                                  (std::is_same_v<big_mod_t, T> || detail::is_integral_v<T>), \
                              int> = 0>                                                       \
    constexpr auto& operator OP_ASSIGN_(big_mod_t & a, const T & b) noexcept {                \
        detail::assert_equal_ops_in_operands(a, b);                                           \
        a.ops().METHOD_(a.raw_base(), detail::convert_to_raw_base(b, a.ops()));               \
        return a;                                                                             \
    }

#define NIL_CO3_MP_MODULAR_BIG_UINT_UNARY_TEMPLATE \
    template<typename big_mod_t, std::enable_if_t<detail::is_big_mod_v<big_mod_t>, int> = 0>

    NIL_CO3_MP_MODULAR_BIG_UINT_OPERATOR_IMPL(+, +=, add)

    NIL_CO3_MP_MODULAR_BIG_UINT_UNARY_TEMPLATE
    constexpr auto& operator++(big_mod_t& a) noexcept {
        a.ops().increment(a.raw_base());
        return a;
    }

    NIL_CO3_MP_MODULAR_BIG_UINT_UNARY_TEMPLATE
    constexpr auto operator++(big_mod_t& a, int) noexcept {
        auto copy = a;
        ++a;
        return copy;
    }

    NIL_CO3_MP_MODULAR_BIG_UINT_UNARY_TEMPLATE
    constexpr auto operator+(const big_mod_t& a) noexcept { return a; }

    NIL_CO3_MP_MODULAR_BIG_UINT_OPERATOR_IMPL(-, -=, subtract)

    NIL_CO3_MP_MODULAR_BIG_UINT_UNARY_TEMPLATE
    constexpr auto& operator--(big_mod_t& a) noexcept {
        a.ops().decrement(a.raw_base());
        return a;
    }

    NIL_CO3_MP_MODULAR_BIG_UINT_UNARY_TEMPLATE
    constexpr auto operator--(big_mod_t& a, int) noexcept {
        auto copy = a;
        --a;
        return copy;
    }

    NIL_CO3_MP_MODULAR_BIG_UINT_UNARY_TEMPLATE
    constexpr big_mod_t operator-(const big_mod_t& a) noexcept {
        big_mod_t result = a;
        result.negate();
        return result;
    }

    NIL_CO3_MP_MODULAR_BIG_UINT_OPERATOR_IMPL(*, *=, mul)

#undef NIL_CO3_MP_MODULAR_BIG_UINT_UNARY_TEMPLATE
#undef NIL_CO3_MP_MODULAR_BIG_UINT_OPERATOR_IMPL

    // Hash

    template<const auto& modulus, template<std::size_t> typename modular_ops_template>
    constexpr std::size_t hash_value(
        const big_mod_ct_impl<modulus, modular_ops_template>& val) noexcept {
        return hash_value(val.raw_base());
    }

    template<std::size_t Bits, template<std::size_t> typename modular_ops_template>
    constexpr std::size_t hash_value(
        const big_mod_rt_impl<Bits, modular_ops_template>& val) noexcept {
        std::size_t result = 0;
        boost::hash_combine(result, val.base());
        boost::hash_combine(result, val.mod());
        return result;
    }

    // IO

    template<typename T, std::enable_if_t<detail::is_big_mod_v<T>, int> = 0>
    std::ostream& operator<<(std::ostream& os, const T& value) {
        os << value.str(os.flags());
        return os;
    }

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
