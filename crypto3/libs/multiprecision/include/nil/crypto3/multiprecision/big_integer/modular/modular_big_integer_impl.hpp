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

#include <ios>
#include <string>
#include <tuple>
#include <type_traits>

#include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"
#include "nil/crypto3/multiprecision/big_integer/modular/modular_params.hpp"

namespace nil::crypto3::multiprecision {
    // fixed precision modular big integer which supports compile-time execution
    template<typename big_integer_t, typename modular_params_storage_t>
    class modular_big_integer {
      public:
        constexpr static auto Bits = big_integer_t::Bits;
        using limb_type = typename big_integer_t::limb_type;
        using double_limb_type = typename big_integer_t::double_limb_type;
        using modular_params_t = modular_params<big_integer_t>;
        using Backend_type = big_integer_t;

        using unsigned_types = typename big_integer_t::unsigned_types;
        using signed_types = typename big_integer_t::signed_types;

      protected:
        using policy_type = typename modular_params_t::policy_type;
        using Backend_padded_limbs = typename policy_type::Backend_padded_limbs;
        using Backend_doubled_limbs = typename policy_type::Backend_doubled_limbs;
        modular_params_storage_t modular_params_storage;

      public:
        // This version of conversion
        constexpr typename big_integer_t::cpp_int_type to_cpp_int() const {
            big_integer_t tmp;
            modular_params_storage.modular_params().adjust_regular(tmp, this->base_data());
            return tmp.to_cpp_int();
        }

        constexpr auto mod_data() { return modular_params_storage.modular_params(); }
        constexpr auto mod_data() const { return modular_params_storage.modular_params(); }

        constexpr big_integer_t& base_data() { return m_base; }
        constexpr const big_integer_t& base_data() const { return m_base; }

        constexpr modular_big_integer() {}

        constexpr modular_big_integer(const modular_big_integer& o) : m_base(o.base_data()) {
            modular_params_storage.set_modular_params(o.modular_params_storage.modular_params());
        }

        constexpr modular_big_integer(modular_big_integer&& o) noexcept
            : m_base(std::move(o.base_data())) {
            modular_params_storage.set_modular_params(
                std::move(o.modular_params_storage.modular_params()));
        }

        template<typename UI, typename std::enable_if_t<std::is_integral_v<UI> &&
                                                        std::is_unsigned_v<UI>> const* = nullptr>
        constexpr modular_big_integer(UI b, const big_integer_t& m) : m_base(limb_type(b)) {
            modular_params_storage.set_modular_params(m);
            modular_params_storage.modular_params().adjust_modular(m_base);
        }

        // A method for converting a signed integer to a modular adaptor. We are not supposed to
        // have this, but in the code we already have conversion for an 'int' into modular type. In
        // the future we must remove.
        template<typename SI, typename std::enable_if_t<std::is_integral_v<SI> &&
                                                        std::is_signed_v<SI>> const* = nullptr>
        constexpr modular_big_integer(SI b) : m_base(limb_type(0u)) {
            if (b >= 0) {
                m_base = static_cast<limb_type>(b);
            } else {
                m_base = modular_params_storage.modular_params().get_mod();
                eval_subtract(m_base, static_cast<limb_type>(-b));
            }

            // This method must be called only for compile time modular params.
            // modular_params_storage.set_modular_params(m);
            modular_params_storage.modular_params().adjust_modular(m_base);
        }

        template<typename UI, typename std::enable_if_t<std::is_integral_v<UI> &&
                                                        std::is_unsigned_v<UI>> const* = nullptr>
        constexpr modular_big_integer(UI b) : m_base(static_cast<limb_type>(b)) {
            // This method must be called only for compile time modular params.
            // modular_params_storage.set_modular_params(m);
            modular_params_storage.modular_params().adjust_modular(m_base);
        }

        template<typename SI, typename std::enable_if_t<std::is_integral_v<SI> &&
                                                        std::is_signed_v<SI>> const* = nullptr>
        constexpr modular_big_integer(SI b, const modular_params_t& m) : m_base(limb_type(0u)) {
            if (b >= 0) {
                m_base = static_cast<limb_type>(b);
            } else {
                m_base = modular_params_storage.modular_params().get_mod();
                eval_subtract(m_base, static_cast<limb_type>(-b));
            }

            modular_params_storage.set_modular_params(m);
            modular_params_storage.modular_params().adjust_modular(m_base);
        }

        template<typename UI, typename std::enable_if_t<std::is_integral_v<UI> &&
                                                        std::is_unsigned_v<UI>> const* = nullptr>
        constexpr modular_big_integer(UI b, const modular_params_t& m)
            : m_base(static_cast<limb_type>(b)) {
            modular_params_storage.set_modular_params(m);
            modular_params_storage.modular_params().adjust_modular(m_base);
        }

        // TODO
        // // We may consider to remove this constructor later, and set Bits2 to Bits only,
        // // but we need it for use cases from h2f/h2c,
        // // where a larger number of 512 or 256 bits is passed to a field of 255 or 254 bits.
        // template<unsigned Bits2>
        // constexpr modular_big_integer(const number<big_integer<Bits2>> &b,
        //                                          const number<big_integer_t> &m) {
        //     modular_params_storage.set_modular_params(m.big_integer_t());
        //     modular_params_storage.modular_params().adjust_modular(m_base, b.big_integer_t());
        // }

        // We may consider to remove this constructor later, and set Bits2 to Bits only,
        // but we need it for use cases from h2f/h2c,
        // where a larger number of 512 or 256 bits is passed to a field of 255 or 254 bits.
        template<unsigned Bits2>
        constexpr modular_big_integer(const big_integer<Bits2>& b, const modular_params_t& m) {
            modular_params_storage.set_modular_params(m);
            modular_params_storage.modular_params().adjust_modular(m_base, b);
        }

        // We may consider to remove this constructor later, and set Bits2 to Bits only,
        // but we need it for use cases from h2f/h2c,
        // where a larger number of 512 or 256 bits is passed to a field of 255 or 254 bits.
        template<unsigned Bits2>
        constexpr explicit modular_big_integer(const big_integer<Bits2>& b) {
            // This method must be called only for compile time modular params.
            // modular_params_storage.set_modular_params(m);
            modular_params_storage.modular_params().adjust_modular(m_base, b);
        }

        // This function sets default modulus value to zero to make sure it fails if not used with
        // compile-time fixed modulus.
        modular_big_integer& operator=(const char* s) {
            using ui_type = typename std::tuple_element<0, unsigned_types>::type;
            ui_type zero = 0u;

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
                    modular_params_storage.set_modular_params(part.c_str());
                } else {
                    modular_params_storage.set_modular_params(zero);
                }
            } else {
                m_base = s;
                modular_params_storage.set_modular_params(zero);
            }
            return *this;
        }

        constexpr bool compare_eq(const modular_big_integer& o) const {
            return !(modular_params_storage.modular_params())
                        .compare(o.modular_params_storage.modular_params()) &&
                   !base_data().compare(o.base_data());
        }

        template<class T>
        constexpr int compare_eq(const T& val) const {
            return !base_data().compare(val);
        }

        constexpr modular_big_integer& operator=(const modular_big_integer& o) {
            m_base = o.base_data();
            modular_params_storage.set_modular_params(o.modular_params_storage.modular_params());

            return *this;
        }

        constexpr modular_big_integer& operator=(modular_big_integer&& o) noexcept {
            m_base = o.base_data();
            modular_params_storage.set_modular_params(o.modular_params_storage.modular_params());

            return *this;
        }

        ~modular_big_integer() = default;

        // If we want to print a value, we must first convert it back to normal form.
        inline std::string str(std::streamsize dig, std::ios_base::fmtflags f) const {
            big_integer_t tmp;
            modular_params_storage.modular_params().adjust_regular(tmp, m_base);
            return tmp.str(dig, f);
        }

        inline constexpr void negate() {
            if (m_base == m_zero) {
                auto initial_m_base = m_base;
                m_base = modular_params_storage.modular_params().get_mod();
                eval_subtract(m_base, initial_m_base);
            }
        }

      protected:
        big_integer_t m_base;
        static constexpr big_integer_t m_zero =
            static_cast<typename std::tuple_element<0, unsigned_types>::type>(0u);
        ;
    };

    template<unsigned Bits, typename big_integer_t1, typename big_integer_t2,
             typename modular_params_storage_t>
    constexpr void assign_components(
        modular_big_integer<big_integer<Bits>, modular_params_storage_t>& result,
        const big_integer_t1& a, const big_integer_t2& b) {
        BOOST_ASSERT_MSG(Bits == eval_msb(b) + 1,
                         "modulus precision should match used big_integer_t");

        result.set_modular_params(b);
        result.modular_params().adjust_modular(result.base_data(), a);
    }
}  // namespace nil::crypto3::multiprecision
