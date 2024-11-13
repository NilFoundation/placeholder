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

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_integer/modular/modular_big_integer.hpp"

#include <climits>
#include <cstddef>
#include <ostream>
#include <string>
#include <type_traits>

#include "nil/crypto3/multiprecision/big_integer/big_integer_impl.hpp"
#include "nil/crypto3/multiprecision/big_integer/detail/assert.hpp"
#include "nil/crypto3/multiprecision/big_integer/modular/modular_ops.hpp"
#include "nil/crypto3/multiprecision/big_integer/modular/modular_ops_storage.hpp"

namespace nil::crypto3::multiprecision {
    namespace detail {
        template<std::size_t Bits_, typename modular_ops_storage_t>
        class modular_big_integer_impl {
          public:
            constexpr static auto Bits = Bits_;
            using big_integer_t = big_integer<Bits>;
            using limb_type = typename big_integer_t::limb_type;
            using double_limb_type = typename big_integer_t::double_limb_type;
            using modular_ops_t = typename modular_ops_storage_t::modular_ops_t;

            // Constructors

          protected:
            template<std::size_t Bits2>
            inline constexpr modular_big_integer_impl(const big_integer<Bits2>& x,
                                                      modular_ops_storage_t&& modular_ops_storage)
                : m_modular_ops_storage(std::move(modular_ops_storage)) {
                ops().adjust_modular(m_raw_base, x);
            }

          public:
            // Comparison

            constexpr bool compare_eq(const modular_big_integer_impl& o) const {
                return ops().compare_eq(o.ops()) && m_raw_base == o.m_raw_base;
            }

            inline constexpr big_integer_t base() const {
                return ops().adjusted_regular(m_raw_base);
            }
            inline constexpr const big_integer_t& mod() const { return ops().get_mod(); }

            // String conversion

            inline constexpr std::string str() const {
                return base().str() + " mod " + mod().str();
            }

            // Mathemetical operations

            inline constexpr void negate() {
                if (!is_zero(m_raw_base)) {
                    auto initial_m_base = m_raw_base;
                    m_raw_base = mod();
                    m_raw_base -= initial_m_base;
                }
            }

            constexpr auto& raw_base() { return m_raw_base; }
            constexpr const auto& raw_base() const { return m_raw_base; }

            constexpr auto& ops() { return m_modular_ops_storage.ops(); }
            constexpr const auto& ops() const { return m_modular_ops_storage.ops(); }

          protected:
            modular_ops_storage_t m_modular_ops_storage;

            big_integer_t m_raw_base;
        };
    }  // namespace detail

    template<const auto& modulus, template<typename> typename modular_ops_template>
    struct modular_big_integer_ct_impl
        : public detail::modular_big_integer_impl<
              std::decay_t<decltype(modulus)>::Bits,
              detail::modular_ops_storage_ct<modulus, modular_ops_template>> {
        using base_type = detail::modular_big_integer_impl<
            std::decay_t<decltype(modulus)>::Bits,
            detail::modular_ops_storage_ct<modulus, modular_ops_template>>;

        using typename base_type::big_integer_t;

        constexpr modular_big_integer_ct_impl() : base_type(big_integer_t(0u), {}) {}

        template<std::size_t Bits2>
        constexpr modular_big_integer_ct_impl(const big_integer<Bits2>& b) : base_type(b, {}) {
            this->ops().adjust_modular(this->m_raw_base, b);
        }

        // A method for converting a signed integer to a modular adaptor.
        // TODO: We are not supposed to
        // have this, but in the code we already have conversion for an 'int' into modular type.
        // In the future we must remove.
        template<typename SI,
                 typename std::enable_if_t<std::is_integral_v<SI> && std::is_signed_v<SI>, int> = 0>
        constexpr modular_big_integer_ct_impl(SI b)
            : base_type(big_integer<sizeof(SI) * CHAR_BIT>(b), {}) {
            if (b < 0) {
                this->negate();
            }
        }

        template<typename UI, typename std::enable_if_t<
                                  std::is_integral_v<UI> && std::is_unsigned_v<UI>, int> = 0>
        constexpr modular_big_integer_ct_impl(UI b)
            : base_type(big_integer<sizeof(UI) * CHAR_BIT>(b), {}) {}

        template<std::size_t Bits2>
        inline constexpr modular_big_integer_ct_impl with_replaced_base(
            const big_integer<Bits2>& b) const {
            return modular_big_integer_ct_impl(b);
        }
    };

    template<std::size_t Bits, template<typename> typename modular_ops_template>
    struct modular_big_integer_rt_impl
        : public detail::modular_big_integer_impl<
              Bits, detail::modular_ops_storage_rt<big_integer<Bits>, modular_ops_template>> {
        using base_type = detail::modular_big_integer_impl<
            Bits, detail::modular_ops_storage_rt<big_integer<Bits>, modular_ops_template>>;

        using typename base_type::big_integer_t;

        template<typename SI,
                 std::enable_if_t<std::is_integral_v<SI> && std::is_signed_v<SI>, int> = 0>
        constexpr modular_big_integer_rt_impl(SI b, const big_integer_t& m)
            : base_type(big_integer<sizeof(SI) * CHAR_BIT>(std::abs(b)), m) {
            if (b < 0) {
                this->negate();
            }
        }

        template<std::size_t Bits2>
        constexpr modular_big_integer_rt_impl(const big_integer<Bits2>& b, const big_integer_t& m)
            : base_type(b, m) {}

        template<typename UI, typename std::enable_if_t<
                                  std::is_integral_v<UI> && std::is_unsigned_v<UI>, int> = 0>
        constexpr modular_big_integer_rt_impl(UI b, const big_integer_t& m)
            : base_type(big_integer<sizeof(UI) * CHAR_BIT>(b), m) {}

        template<std::size_t Bits2>
        inline constexpr modular_big_integer_rt_impl with_replaced_base(
            const big_integer<Bits2>& b) const {
            auto copy = *this;
            copy.m_raw_base = b;
            copy.ops().adjust_modular(copy.m_raw_base);
            return copy;
        }
    };

    namespace detail {
        template<typename T>
        constexpr bool is_modular_big_integer_v = false;

        template<const auto& modulus, template<typename> typename modular_ops_storage_t>
        constexpr bool
            is_modular_big_integer_v<modular_big_integer_ct_impl<modulus, modular_ops_storage_t>> =
                true;

        template<std::size_t Bits, template<typename> typename modular_ops_storage_t>
        constexpr bool
            is_modular_big_integer_v<modular_big_integer_rt_impl<Bits, modular_ops_storage_t>> =
                true;

        template<typename T>
        constexpr bool is_modular_integral_v =
            std::is_integral_v<T> || detail::is_big_integer_v<T> || is_modular_big_integer_v<T>;

        template<typename T, std::enable_if_t<detail::is_modular_big_integer_v<T>, int> = 0>
        constexpr std::size_t get_bits() {
            return T::Bits;
        }
    }  // namespace detail

    // Comparison

#define NIL_CO3_MP_MODULAR_BIG_INTEGER_COMPARISON_IMPL(op)                 \
    template<typename T1, typename T2,                                     \
             std::enable_if_t<detail::is_modular_big_integer_v<T1> &&      \
                                  detail::is_modular_big_integer_v<T2>,    \
                              int> = 0>                                    \
    inline constexpr bool operator op(const T1& a, const T2& b) noexcept { \
        return a.compare_eq(b) op true;                                    \
    }

    NIL_CO3_MP_MODULAR_BIG_INTEGER_COMPARISON_IMPL(==)
    NIL_CO3_MP_MODULAR_BIG_INTEGER_COMPARISON_IMPL(!=)
#undef NIL_CO3_MP_MODULAR_BIG_INTEGER_COMPARISON_IMPL

#define NIL_CO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE                                           \
    template<                                                                                      \
        typename T1, typename T2,                                                                  \
        std::enable_if_t<std::is_same_v<T1, T2> && detail::is_modular_big_integer_v<T1>, int> = 0, \
        typename largest_t = T1>

#define NIL_CO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE                      \
    template<typename modular_big_integer_t, typename T,                                 \
             std::enable_if_t<detail::is_modular_big_integer_v<modular_big_integer_t> && \
                                  std::is_same_v<modular_big_integer_t, T>,              \
                              int> = 0>

#define NIL_CO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE \
    template<typename modular_big_integer_t,          \
             std::enable_if_t<detail::is_modular_big_integer_v<modular_big_integer_t>, int> = 0>

    // Arithmetic operations

    NIL_CO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator+(const T1& a, const T2& b) noexcept {
        NIL_CO3_MP_ASSERT(a.ops().compare_eq(b.ops()));
        largest_t result = a;
        a.ops().add(result.raw_base(), b.raw_base());
        return result;
    }
    NIL_CO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator+=(modular_big_integer_t& a, const T& b) noexcept {
        NIL_CO3_MP_ASSERT(a.ops().compare_eq(b.ops()));
        a.ops().add(a.raw_base(), b.raw_base());
        return a;
    }
    NIL_CO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto& operator++(modular_big_integer_t& a) noexcept {
        ++a.raw_base();
        if (a.raw_base() == a.mod()) {
            a.raw_base() = 0u;
        }
        return a;
    }
    NIL_CO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator++(modular_big_integer_t& a, int) noexcept {
        auto copy = a;
        ++a;
        return copy;
    }
    NIL_CO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator+(const modular_big_integer_t& a) noexcept { return a; }

    namespace detail {
        template<std::size_t Bits, typename modular_ops_t>
        constexpr void subtract(modular_big_integer_impl<Bits, modular_ops_t>& result,
                                const modular_big_integer_impl<Bits, modular_ops_t>& o) {
            if (result.raw_base() < o.raw_base()) {
                auto v = result.mod();
                v -= o.raw_base();
                result.raw_base() += v;
            } else {
                result.raw_base() -= o.raw_base();
            }
        }
    }  // namespace detail

    NIL_CO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator-(const T1& a, const T2& b) noexcept {
        largest_t result = a;
        detail::subtract(result, b);
        return result;
    }
    NIL_CO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator-=(modular_big_integer_t& a, const T& b) {
        detail::subtract(a, b);
        return a;
    }
    NIL_CO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto& operator--(modular_big_integer_t& a) noexcept {
        if (is_zero(a.raw_base())) {
            a.raw_base() = a.mod();
        }
        --a.raw_base();
        return a;
    }
    NIL_CO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator--(modular_big_integer_t& a, int) noexcept {
        auto copy = a;
        --a;
        return copy;
    }

    NIL_CO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr modular_big_integer_t operator-(const modular_big_integer_t& a) noexcept {
        modular_big_integer_t result = a;
        result.negate();
        return result;
    }

    NIL_CO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator*(const T1& a, const T2& b) noexcept {
        NIL_CO3_MP_ASSERT(a.ops().compare_eq(b.ops()));
        largest_t result = a;
        a.ops().mul(result.raw_base(), b.raw_base());
        return result;
    }
    NIL_CO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator*=(modular_big_integer_t& a, const T& b) noexcept {
        NIL_CO3_MP_ASSERT(a.ops().compare_eq(b.ops()));
        a.ops().mul(a.raw_base(), b.raw_base());
        return a;
    }

    NIL_CO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator/(const T1& a, const T2& b) noexcept {
        largest_t result;
        eval_divide(result, a, b);
        return result;
    }
    NIL_CO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator/=(modular_big_integer_t& a, const T& b) noexcept {
        eval_divide(a, b);
        return a;
    }

    template<std::size_t Bits, typename modular_ops_t>
    constexpr bool is_zero(
        const detail::modular_big_integer_impl<Bits, modular_ops_t>& val) noexcept {
        return is_zero(val.raw_base());
    }

    // Hash

    template<std::size_t Bits, typename modular_ops_t>
    inline constexpr std::size_t hash_value(
        const detail::modular_big_integer_impl<Bits, modular_ops_t>& val) noexcept {
        return hash_value(val.raw_base());
    }

    // IO

    template<typename T, std::enable_if_t<detail::is_modular_big_integer_v<T>, int> = 0>
    std::ostream& operator<<(std::ostream& os, const T& value) {
        os << value.str();
        return os;
    }

#undef NIL_CO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
#undef NIL_CO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
#undef NIL_CO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE

    template<const auto& modulus>
    using montgomery_modular_big_integer =
        modular_big_integer_ct_impl<modulus, detail::montgomery_modular_ops>;
    template<std::size_t Bits>
    using montgomery_modular_big_integer_rt =
        modular_big_integer_rt_impl<Bits, detail::montgomery_modular_ops>;
    template<const auto& modulus>
    using modular_big_integer = modular_big_integer_ct_impl<modulus, detail::barrett_modular_ops>;
    template<std::size_t Bits>
    using modular_big_integer_rt = modular_big_integer_rt_impl<Bits, detail::barrett_modular_ops>;
    template<const auto& modulus>
    using auto_modular_big_integer =
        std::conditional_t<detail::check_montgomery_constraints(modulus),
                           montgomery_modular_big_integer<modulus>, modular_big_integer<modulus>>;
}  // namespace nil::crypto3::multiprecision
