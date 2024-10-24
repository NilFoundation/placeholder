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
#include "nil/crypto3/multiprecision/big_integer/modular/modular_ops.hpp"

namespace nil::crypto3::multiprecision {
    namespace detail {
        // fixed precision modular big integer which supports compile-time execution
        template<typename big_integer_t_, typename modular_ops_storage_t>
        class modular_big_integer_impl {
          public:
            using big_integer_t = big_integer_t_;
            constexpr static auto Bits = big_integer_t::Bits;
            using limb_type = typename big_integer_t::limb_type;
            using double_limb_type = typename big_integer_t::double_limb_type;
            using modular_ops_t = modular_ops<big_integer_t>;

            using unsigned_types = typename big_integer_t::unsigned_types;
            using signed_types = typename big_integer_t::signed_types;

          private:
            using policy_type = typename modular_ops_t::policy_type;
            using big_integer_padded_limbs = typename policy_type::big_integer_padded_limbs;
            using big_integer_doubled_limbs = typename policy_type::big_integer_doubled_limbs;

            // Constructors

          protected:
            inline constexpr modular_big_integer_impl(modular_ops_storage_t&& modular_ops_storage)
                : m_modular_ops_storage(std::move(modular_ops_storage)) {}

          public:
            // Comparison

            constexpr bool compare_eq(const modular_big_integer_impl& o) const {
                // TODO(ioxid): ensure modulus comparison is done in compile time when possible
                return ops().compare_eq(o.ops()) && m_base == o.m_base;
            }

            template<class T>
            constexpr int compare_eq(const T& val) const {
                // TODO(ioxid): should compare adjusted?
                return m_base == val;
            }

            // cpp_int conversion

            constexpr typename big_integer_t::cpp_int_type to_cpp_int() const {
                return ops().adjusted_regular(m_base).to_cpp_int();
            }

            // String conversion

            inline std::string str(std::streamsize digits = 0,
                                   std::ios_base::fmtflags f = std::ios_base::fmtflags(0)) const {
                // TODO(ioxid): add module to output
                return ops().adjusted_regular(m_base).str(digits, f);
            }

            // TODO(ioxid): why is it here
            // Mathemetical operations

            inline constexpr void negate() {
                if (m_base != m_zero) {
                    auto initial_m_base = m_base;
                    m_base = ops().get_mod();
                    m_base -= initial_m_base;
                }
            }

            // TODO(ioxid): who needs this and why is it an assignment operator
            // This function sets default modulus value to zero to make sure it fails if not used
            // with compile-time fixed modulus.
            modular_big_integer_impl& operator=(const char* s) {
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
            static constexpr big_integer_t m_zero =
                static_cast<typename std::tuple_element<0, unsigned_types>::type>(0u);
            ;
        };

        template<unsigned Bits, typename big_integer_t1, typename big_integer_t2,
                 typename modular_ops_storage_t>
        constexpr void assign_components(
            modular_big_integer_impl<big_integer<Bits>, modular_ops_storage_t>& result,
            const big_integer_t1& a, const big_integer_t2& b) {
            BOOST_ASSERT_MSG(Bits == msb(b) + 1,
                             "modulus precision should match used big_integer_t");

            result.set_modular_ops(b);
            result.ops().adjust_modular(result.base_data(), a);
        }
    }  // namespace detail

    template<const auto& modulus>
    struct modular_big_integer_ct
        : public detail::modular_big_integer_impl<
              std::decay_t<decltype(modulus)>,
              detail::modular_ops_storage_ct<std::decay_t<decltype(modulus)>, modulus>> {
        using base_type = detail::modular_big_integer_impl<
            std::decay_t<decltype(modulus)>,
            detail::modular_ops_storage_ct<std::decay_t<decltype(modulus)>, modulus>>;

        using typename base_type::big_integer_t;

        constexpr modular_big_integer_ct() : base_type({}) {}

        template<unsigned Bits2>
        constexpr explicit modular_big_integer_ct(const big_integer<Bits2>& b) : base_type({}) {
            this->ops().adjust_modular(this->m_base, b);
        }

        // A method for converting a signed integer to a modular adaptor. We are not supposed to
        // have this, but in the code we already have conversion for an 'int' into modular type. In
        // the future we must remove.
        template<typename SI,
                 typename std::enable_if_t<std::is_integral_v<SI> && std::is_signed_v<SI>, int> = 0>
        constexpr modular_big_integer_ct(SI b) : base_type({}) {
            if (b >= 0) {
                this->m_base = static_cast<std::make_unsigned_t<SI>>(b);
            } else {
                this->m_base = this->ops().get_mod();
                // TODO(ioxid): should work not just with limb_type
                this->m_base -= static_cast<detail::limb_type>(-b);
            }

            // This method must be called only for compile time modular params.
            // modular_ops_storage.set_modular_ops(m);
            this->ops().adjust_modular(this->m_base);
        }

        template<typename UI, typename std::enable_if_t<
                                  std::is_integral_v<UI> && std::is_unsigned_v<UI>, int> = 0>
        constexpr modular_big_integer_ct(UI b) : base_type({}) {
            this->m_base = b;
            this->ops().adjust_modular(this->m_base);
        }
    };

    template<unsigned Bits>
    struct modular_big_integer_rt
        : public detail::modular_big_integer_impl<
              big_integer<Bits>, detail::modular_ops_storage_rt<big_integer<Bits>>> {
        using base_type =
            detail::modular_big_integer_impl<big_integer<Bits>,
                                             detail::modular_ops_storage_rt<big_integer<Bits>>>;

        using typename base_type::big_integer_t;

          template<typename SI,
                 std::enable_if_t<std::is_integral_v<SI> && std::is_signed_v<SI>, int> = 0>
        constexpr modular_big_integer_rt(SI b, const big_integer_t& m): base_type(m) {
            if (b >= 0) {
                this->m_base = b;
            } else {
                this->m_base = this->ops().get_mod();
                // TODO(ioxid): should work not just with limb_type
                this->m_base -= static_cast<detail::limb_type>(-b);
            }

            this->ops().adjust_modular(this->m_base);
        }

        template<typename UI, typename std::enable_if_t<
                                  std::is_integral_v<UI> && std::is_unsigned_v<UI>, int> = 0>
        constexpr modular_big_integer_rt(UI b, const big_integer_t& m) : base_type(m) {
            this->m_base = b;
            this->ops().adjust_modular(this->m_base);
        }

        // TODO(ioxid): move adjust modular to impl constructor
        template<unsigned Bits2>
        constexpr modular_big_integer_rt(const big_integer<Bits2>& b, const big_integer_t& m)
            : base_type(m) {
            this->ops().adjust_modular(this->m_base, b);
        }
    };
}  // namespace nil::crypto3::multiprecision
