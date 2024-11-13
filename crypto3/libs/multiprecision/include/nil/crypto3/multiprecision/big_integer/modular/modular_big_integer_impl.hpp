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
        template<typename big_integer_t_, typename modular_ops_storage_t>
        class modular_big_integer_impl {
          public:
            using big_integer_t = big_integer_t_;
            constexpr static auto Bits = big_integer_t::Bits;
            using limb_type = typename big_integer_t::limb_type;
            using double_limb_type = typename big_integer_t::double_limb_type;
            using modular_ops_t = typename modular_ops_storage_t::modular_ops_t;

            // Constructors

          protected:
            inline constexpr modular_big_integer_impl(const big_integer_t x,
                                                      modular_ops_storage_t&& modular_ops_storage)
                : m_modular_ops_storage(std::move(modular_ops_storage)) {
                // TODO(ioxid): do we need this?
                // NIL_CO3_MP_ASSERT_MSG(Bits == msb(ops().get_mod()) + 1,
                //                  "modulus precision should match used big_integer");
                ops().adjust_modular(m_base, x);
            }

          public:
            // Comparison

            constexpr bool compare_eq(const modular_big_integer_impl& o) const {
                // TODO(ioxid): ensure modulus comparison is done in compile time when possible
                return ops().compare_eq(o.ops()) && m_base == o.m_base;
            }

            // TODO(ioxid): do we need this? If yes then need to make sure this is not chosen for T
            // = modular_big_integer
            //
            // template<class T> constexpr bool compare_eq(const T& val) const
            // {
            //     return remove_modulus() == val;
            // }

            constexpr big_integer_t remove_modulus() const {
                return ops().adjusted_regular(m_base);
            }

            // String conversion

            inline constexpr std::string str() const {
                // TODO(ioxid): add module to output
                return remove_modulus().str();
            }

            // Mathemetical operations

            inline constexpr void negate() {
                if (!is_zero(m_base)) {
                    auto initial_m_base = m_base;
                    m_base = ops().get_mod();
                    m_base -= initial_m_base;
                }
            }

            // TODO(ioxid): who needs this and why is it an assignment operator
            // This function sets default modulus value to zero to make sure it fails if not used
            // with compile-time fixed modulus.
            modular_big_integer_impl& operator=(const char* s) {
                limb_type zero = 0u;

                if (s && (*s == '(')) {
                    std::string part;
                    const char* p = ++s;
                    while (*p && (*p != ',') && (*p != ')')) {
                        ++p;
                    }
                    part.assign(s, p);
                    if (!part.empty()) {
                        m_base = part.c_str();
                    } else {
                        m_base = zero;
                    }
                    s = p;
                    if (*p && (*p != ')')) {
                        ++p;
                        while (*p && (*p != ')')) {
                            ++p;
                        }
                        part.assign(s + 1, p);
                    } else {
                        part.erase();
                    }
                    if (!part.empty()) {
                        m_modular_ops_storage.set_modular_ops(part.c_str());
                    } else {
                        m_modular_ops_storage.set_modular_ops(zero);
                    }
                } else {
                    m_base = s;
                    m_modular_ops_storage.set_modular_ops(zero);
                }
                return *this;
            }

            constexpr auto& base_data() { return m_base; }
            constexpr const auto& base_data() const { return m_base; }

            constexpr auto& ops() { return m_modular_ops_storage.ops(); }
            constexpr const auto& ops() const { return m_modular_ops_storage.ops(); }

          protected:
            modular_ops_storage_t m_modular_ops_storage;

            big_integer_t m_base;
        };
    }  // namespace detail

    template<const auto& modulus, template<typename> typename modular_ops_template>
    struct modular_big_integer_ct_impl
        : public detail::modular_big_integer_impl<
              std::decay_t<decltype(modulus)>,
              detail::modular_ops_storage_ct<modulus, modular_ops_template>> {
        using base_type = detail::modular_big_integer_impl<
            std::decay_t<decltype(modulus)>,
            detail::modular_ops_storage_ct<modulus, modular_ops_template>>;

        using typename base_type::big_integer_t;

        constexpr modular_big_integer_ct_impl() : base_type({}, {}) {}

        constexpr modular_big_integer_ct_impl(const big_integer_t& b) : base_type(b, {}) {
            this->ops().adjust_modular(this->m_base, b);
        }

        template<std::size_t Bits2>
        constexpr explicit modular_big_integer_ct_impl(const big_integer<Bits2>& b)
            : base_type(b, {}) {
            this->ops().adjust_modular(this->m_base, b);
        }

        // A method for converting a signed integer to a modular adaptor. We are not supposed to
        // have this, but in the code we already have conversion for an 'int' into modular type.
        // In the future we must remove.
        template<typename SI,
                 typename std::enable_if_t<std::is_integral_v<SI> && std::is_signed_v<SI>, int> = 0>
        constexpr modular_big_integer_ct_impl(SI b) : base_type(0u, {}) {
            if (b >= 0) {
                this->m_base = static_cast<std::make_unsigned_t<SI>>(b);
            } else {
                this->m_base = this->ops().get_mod();
                // TODO(ioxid): should work not just with limb_type, and this does not really
                // work (m_base may underflow)
                this->m_base -= static_cast<detail::limb_type>(-b);
            }

            this->ops().adjust_modular(this->m_base);
        }

        template<typename UI, typename std::enable_if_t<
                                  std::is_integral_v<UI> && std::is_unsigned_v<UI>, int> = 0>
        constexpr modular_big_integer_ct_impl(UI b) : base_type(b, {}) {}
    };

    template<std::size_t Bits, template<typename> typename modular_ops_template>
    struct modular_big_integer_rt_impl
        : public detail::modular_big_integer_impl<
              big_integer<Bits>,
              detail::modular_ops_storage_rt<big_integer<Bits>, modular_ops_template>> {
        using base_type = detail::modular_big_integer_impl<
            big_integer<Bits>,
            detail::modular_ops_storage_rt<big_integer<Bits>, modular_ops_template>>;

        using typename base_type::big_integer_t;

        template<typename SI,
                 std::enable_if_t<std::is_integral_v<SI> && std::is_signed_v<SI>, int> = 0>
        constexpr modular_big_integer_rt_impl(SI b, const big_integer_t& m) : base_type(0u, m) {
            if (b >= 0) {
                this->m_base = b;
            } else {
                this->m_base = this->ops().get_mod();
                // TODO(ioxid): should work not just with limb_type, and this does not really
                // work (m_base may underflow)
                this->m_base -= static_cast<detail::limb_type>(-b);
            }

            this->ops().adjust_modular(this->m_base);
        }

        template<typename UI, typename std::enable_if_t<
                                  std::is_integral_v<UI> && std::is_unsigned_v<UI>, int> = 0>
        constexpr modular_big_integer_rt_impl(UI b, const big_integer_t& m) : base_type(b, m) {}

        template<std::size_t Bits2>
        constexpr modular_big_integer_rt_impl(const big_integer<Bits2>& b, const big_integer_t& m)
            : base_type(b, m) {}
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

// TODO(ioxid): comparison with big_integer and basic types (including signed)
#define CRYPTO3_MP_MODULAR_BIG_INTEGER_COMPARISON_IMPL(op)                 \
    template<typename T1, typename T2,                                     \
             std::enable_if_t<detail::is_modular_big_integer_v<T1> &&      \
                                  detail::is_modular_big_integer_v<T2>,    \
                              int> = 0>                                    \
    inline constexpr bool operator op(const T1& a, const T2& b) noexcept { \
        return a.compare_eq(b) op true;                                    \
    }

    CRYPTO3_MP_MODULAR_BIG_INTEGER_COMPARISON_IMPL(==)
    CRYPTO3_MP_MODULAR_BIG_INTEGER_COMPARISON_IMPL(!=)
#undef CRYPTO3_MP_MODULAR_BIG_INTEGER_COMPARISON_IMPL

    // TODO(ioxid): choose result type
#define CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE                                           \
    template<                                                                                      \
        typename T1, typename T2,                                                                  \
        std::enable_if_t<detail::is_modular_integral_v<T1> && detail::is_modular_integral_v<T2> && \
                             (detail::is_modular_big_integer_v<T1> ||                              \
                              detail::is_modular_big_integer_v<T2>),                               \
                         int> = 0,                                                                 \
        typename largest_t = T1>

#define CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE                      \
    template<typename modular_big_integer_t, typename T,                                 \
             std::enable_if_t<detail::is_modular_big_integer_v<modular_big_integer_t> && \
                                  detail::is_modular_integral_v<T> &&                    \
                                  detail::get_bits<T>() <= modular_big_integer_t::Bits,  \
                              int> = 0>

#define CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE \
    template<typename modular_big_integer_t,          \
             std::enable_if_t<detail::is_modular_big_integer_v<modular_big_integer_t>, int> = 0>

    // Arithmetic operations

    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator+(const T1& a, const T2& b) noexcept {
        NIL_CO3_MP_ASSERT(a.ops().compare_eq(b.ops()));
        largest_t result = a;
        a.ops().add(result.base_data(), b.base_data());
        return result;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator+=(modular_big_integer_t& a, const T& b) noexcept {
        NIL_CO3_MP_ASSERT(a.ops().compare_eq(b.ops()));
        a.ops().add(a.base_data(), b.base_data());
        return a;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto& operator++(modular_big_integer_t& a) noexcept {
        // TODO(ioxid): implement faster
        a += static_cast<modular_big_integer_t>(1u);
        return a;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator++(modular_big_integer_t& a, int) noexcept {
        auto copy = a;
        // TODO(ioxid): implement faster
        a += static_cast<modular_big_integer_t>(1u);
        return copy;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator+(const modular_big_integer_t& a) noexcept { return a; }

    namespace detail {
        template<std::size_t Bits, typename modular_ops_t>
        constexpr void subtract(
            modular_big_integer_impl<big_integer<Bits>, modular_ops_t>& result,
            const modular_big_integer_impl<big_integer<Bits>, modular_ops_t>& o) {
            if (result.base_data() < o.base_data()) {
                auto v = result.ops().get_mod();
                v -= o.base_data();
                result.base_data() += v;
            } else {
                result.base_data() -= o.base_data();
            }
        }
    }  // namespace detail

    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator-(const T1& a, const T2& b) noexcept {
        largest_t result = a;
        detail::subtract(result, b);
        return result;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator-=(modular_big_integer_t& a, const T& b) {
        detail::subtract(a, b);
        return a;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto& operator--(modular_big_integer_t& a) noexcept {
        // TODO(ioxid): implement faster
        a -= static_cast<modular_big_integer_t>(1u);
        return a;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator--(modular_big_integer_t& a, int) noexcept {
        auto copy = a;
        // TODO(ioxid): implement faster
        a -= static_cast<modular_big_integer_t>(1u);
        return copy;
    }

    CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr modular_big_integer_t operator-(const modular_big_integer_t& a) noexcept {
        modular_big_integer_t result = a;
        result.negate();
        return result;
    }

    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator*(const T1& a, const T2& b) noexcept {
        NIL_CO3_MP_ASSERT(a.ops().compare_eq(b.ops()));
        largest_t result = a;
        a.ops().mul(result.base_data(), b.base_data());
        return result;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator*=(modular_big_integer_t& a, const T& b) noexcept {
        NIL_CO3_MP_ASSERT(a.ops().compare_eq(b.ops()));
        a.ops().mul(a.base_data(), b.base_data());
        return a;
    }

    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator/(const T1& a, const T2& b) noexcept {
        largest_t result;
        eval_divide(result, a, b);
        return result;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator/=(modular_big_integer_t& a, const T& b) noexcept {
        eval_divide(a, b);
        return a;
    }

    template<class big_integer_t, typename modular_ops_t>
    constexpr bool is_zero(
        const detail::modular_big_integer_impl<big_integer_t, modular_ops_t>& val) noexcept {
        return is_zero(val.base_data());
    }

    // Hash

    template<typename big_integer_t, typename modular_ops_t>
    inline constexpr std::size_t hash_value(
        const detail::modular_big_integer_impl<big_integer_t, modular_ops_t>& val) noexcept {
        // TODO(ioxid): also hash modulus for runtime type
        return hash_value(val.base_data());
    }

    // IO

    template<typename T, std::enable_if_t<detail::is_modular_big_integer_v<T>, int> = 0>
    std::ostream& operator<<(std::ostream& os, const T& value) {
        os << value.str();
        return os;
    }

#undef CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
#undef CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
#undef CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE

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
