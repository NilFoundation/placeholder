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
#include <ostream>
#include <string>
#include <type_traits>

#include "nil/crypto3/multiprecision/big_int/big_uint_impl.hpp"
#include "nil/crypto3/multiprecision/big_int/detail/assert.hpp"
#include "nil/crypto3/multiprecision/big_int/modular/modular_ops.hpp"
#include "nil/crypto3/multiprecision/big_int/modular/modular_ops_storage.hpp"

namespace nil::crypto3::multiprecision {
    namespace detail {
        template<std::size_t Bits_, typename modular_ops_storage_t>
        class big_mod_impl {
          public:
            static constexpr std::size_t Bits = Bits_;
            using big_uint_t = big_uint<Bits>;
            using modular_ops_t = typename modular_ops_storage_t::modular_ops_t;

            // Constructors

          protected:
            template<std::size_t Bits2>
            constexpr big_mod_impl(const big_uint<Bits2>& x,
                                   modular_ops_storage_t&& modular_ops_storage)
                : m_modular_ops_storage(std::move(modular_ops_storage)) {
                ops().adjust_modular(m_raw_base, x);
            }

          public:
            // Comparison

            constexpr bool compare_eq(const big_mod_impl& o) const {
                return ops().compare_eq(o.ops()) && m_raw_base == o.m_raw_base;
            }

            constexpr big_uint_t base() const { return ops().adjusted_regular(m_raw_base); }
            constexpr const big_uint_t& mod() const { return ops().mod(); }

            // String conversion

            constexpr std::string str() const { return base().str() + " mod " + mod().str(); }

            // Mathemetical operations

            constexpr void negate() {
                if (!is_zero(m_raw_base)) {
                    auto initial_m_base = m_raw_base;
                    m_raw_base = mod();
                    m_raw_base -= initial_m_base;
                }
            }

            // Accessing raw base value. Should only be used internally by multiprecision library.
            constexpr auto& raw_base() { return m_raw_base; }
            constexpr const auto& raw_base() const { return m_raw_base; }

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

        constexpr big_mod_ct_impl() : base_type(big_uint_t(0u), {}) {}

        template<std::size_t Bits2>
        constexpr big_mod_ct_impl(const big_uint<Bits2>& b) : base_type(b, {}) {
            this->ops().adjust_modular(this->m_raw_base, b);
        }

        // A method for converting a signed integer to a modular adaptor.
        //
        // TODO: We are not supposed to have this, but in the code we already have conversions from
        // 'int' into modular type. In the future we must remove this.
        template<typename SI,
                 typename std::enable_if_t<std::is_integral_v<SI> && std::is_signed_v<SI>, int> = 0>
        constexpr big_mod_ct_impl(SI b)
            : base_type(big_uint<sizeof(SI) * CHAR_BIT>(std::abs(b)), {}) {
            if (b < 0) {
                this->negate();
            }
        }

        template<typename UI, typename std::enable_if_t<
                                  std::is_integral_v<UI> && std::is_unsigned_v<UI>, int> = 0>
        constexpr big_mod_ct_impl(UI b) : base_type(big_uint<sizeof(UI) * CHAR_BIT>(b), {}) {}

        template<std::size_t Bits2>
        constexpr big_mod_ct_impl with_replaced_base(const big_uint<Bits2>& b) const {
            return big_mod_ct_impl(b);
        }
    };

    template<std::size_t Bits, template<std::size_t> typename modular_ops_template>
    struct big_mod_rt_impl
        : public detail::big_mod_impl<Bits,
                                      detail::modular_ops_storage_rt<Bits, modular_ops_template>> {
        using base_type =
            detail::big_mod_impl<Bits, detail::modular_ops_storage_rt<Bits, modular_ops_template>>;

        using typename base_type::big_uint_t;

        // A method for converting a signed integer to a modular adaptor.
        //
        // TODO: We are not supposed to have this, but in the code we already have conversions from
        // 'int' into modular type. In the future we must remove this.
        template<typename SI,
                 std::enable_if_t<std::is_integral_v<SI> && std::is_signed_v<SI>, int> = 0>
        constexpr big_mod_rt_impl(SI b, const big_uint_t& m)
            : base_type(big_uint<sizeof(SI) * CHAR_BIT>(std::abs(b)), m) {
            if (b < 0) {
                this->negate();
            }
        }

        template<std::size_t Bits2>
        constexpr big_mod_rt_impl(const big_uint<Bits2>& b, const big_uint_t& m)
            : base_type(b, m) {}

        template<typename UI, typename std::enable_if_t<
                                  std::is_integral_v<UI> && std::is_unsigned_v<UI>, int> = 0>
        constexpr big_mod_rt_impl(UI b, const big_uint_t& m)
            : base_type(big_uint<sizeof(UI) * CHAR_BIT>(b), m) {}

        template<std::size_t Bits2>
        constexpr big_mod_rt_impl with_replaced_base(const big_uint<Bits2>& b) const {
            auto copy = *this;
            copy.m_raw_base = b;
            copy.ops().adjust_modular(copy.m_raw_base);
            return copy;
        }
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
    }  // namespace detail

    // Comparison

#define NIL_CO3_MP_MODULAR_BIG_UINT_COMPARISON_IMPL(op)                                       \
    template<typename T1, typename T2,                                                        \
             std::enable_if_t<detail::is_big_mod_v<T1> && detail::is_big_mod_v<T2>, int> = 0> \
    constexpr bool operator op(const T1& a, const T2& b) noexcept {                           \
        return a.compare_eq(b) op true;                                                       \
    }

    NIL_CO3_MP_MODULAR_BIG_UINT_COMPARISON_IMPL(==)
    NIL_CO3_MP_MODULAR_BIG_UINT_COMPARISON_IMPL(!=)

#undef NIL_CO3_MP_MODULAR_BIG_UINT_COMPARISON_IMPL

    // Arithmetic operations

#define NIL_CO3_MP_MODULAR_BIG_UINT_INTEGRAL_TEMPLATE                                       \
    template<typename T1, typename T2,                                                      \
             std::enable_if_t<std::is_same_v<T1, T2> && detail::is_big_mod_v<T1>, int> = 0, \
             typename largest_t = T1>

#define NIL_CO3_MP_MODULAR_BIG_UINT_INTEGRAL_ASSIGNMENT_TEMPLATE                               \
    template<typename big_mod_t, typename T,                                                   \
             std::enable_if_t<detail::is_big_mod_v<big_mod_t> && std::is_same_v<big_mod_t, T>, \
                              int> = 0>

#define NIL_CO3_MP_MODULAR_BIG_UINT_UNARY_TEMPLATE \
    template<typename big_mod_t, std::enable_if_t<detail::is_big_mod_v<big_mod_t>, int> = 0>

    NIL_CO3_MP_MODULAR_BIG_UINT_INTEGRAL_TEMPLATE
    constexpr auto operator+(const T1& a, const T2& b) noexcept {
        NIL_CO3_MP_ASSERT(a.ops().compare_eq(b.ops()));
        largest_t result = a;
        a.ops().add(result.raw_base(), b.raw_base());
        return result;
    }
    NIL_CO3_MP_MODULAR_BIG_UINT_INTEGRAL_ASSIGNMENT_TEMPLATE
    constexpr auto& operator+=(big_mod_t& a, const T& b) noexcept {
        NIL_CO3_MP_ASSERT(a.ops().compare_eq(b.ops()));
        a.ops().add(a.raw_base(), b.raw_base());
        return a;
    }
    NIL_CO3_MP_MODULAR_BIG_UINT_UNARY_TEMPLATE
    constexpr auto& operator++(big_mod_t& a) noexcept {
        ++a.raw_base();
        if (a.raw_base() == a.mod()) {
            a.raw_base() = 0u;
        }
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

    namespace detail {
        template<std::size_t Bits, typename modular_ops_t>
        constexpr void subtract(big_mod_impl<Bits, modular_ops_t>& result,
                                const big_mod_impl<Bits, modular_ops_t>& o) {
            if (result.raw_base() < o.raw_base()) {
                auto v = result.mod();
                v -= o.raw_base();
                result.raw_base() += v;
            } else {
                result.raw_base() -= o.raw_base();
            }
        }
    }  // namespace detail

    NIL_CO3_MP_MODULAR_BIG_UINT_INTEGRAL_TEMPLATE
    constexpr auto operator-(const T1& a, const T2& b) noexcept {
        largest_t result = a;
        detail::subtract(result, b);
        return result;
    }
    NIL_CO3_MP_MODULAR_BIG_UINT_INTEGRAL_ASSIGNMENT_TEMPLATE
    constexpr auto& operator-=(big_mod_t& a, const T& b) {
        detail::subtract(a, b);
        return a;
    }
    NIL_CO3_MP_MODULAR_BIG_UINT_UNARY_TEMPLATE
    constexpr auto& operator--(big_mod_t& a) noexcept {
        if (is_zero(a.raw_base())) {
            a.raw_base() = a.mod();
        }
        --a.raw_base();
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

    NIL_CO3_MP_MODULAR_BIG_UINT_INTEGRAL_TEMPLATE
    constexpr auto operator*(const T1& a, const T2& b) noexcept {
        NIL_CO3_MP_ASSERT(a.ops().compare_eq(b.ops()));
        largest_t result = a;
        a.ops().mul(result.raw_base(), b.raw_base());
        return result;
    }
    NIL_CO3_MP_MODULAR_BIG_UINT_INTEGRAL_ASSIGNMENT_TEMPLATE
    constexpr auto& operator*=(big_mod_t& a, const T& b) noexcept {
        NIL_CO3_MP_ASSERT(a.ops().compare_eq(b.ops()));
        a.ops().mul(a.raw_base(), b.raw_base());
        return a;
    }

#undef NIL_CO3_MP_MODULAR_BIG_UINT_UNARY_TEMPLATE
#undef NIL_CO3_MP_MODULAR_BIG_UINT_INTEGRAL_ASSIGNMENT_TEMPLATE
#undef NIL_CO3_MP_MODULAR_BIG_UINT_INTEGRAL_TEMPLATE

    // Additional operations

    template<std::size_t Bits, typename modular_ops_t>
    constexpr bool is_zero(const detail::big_mod_impl<Bits, modular_ops_t>& val) noexcept {
        // In barrett form raw_base is the same as base
        // In montgomery form raw_base is base multiplied by r, so it is zero iff base is
        return is_zero(val.raw_base());
    }

    // Hash

    template<std::size_t Bits, typename modular_ops_t>
    constexpr std::size_t hash_value(
        const detail::big_mod_impl<Bits, modular_ops_t>& val) noexcept {
        return hash_value(val.raw_base());
    }

    // IO

    template<typename T, std::enable_if_t<detail::is_big_mod_v<T>, int> = 0>
    std::ostream& operator<<(std::ostream& os, const T& value) {
        os << value.str();
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