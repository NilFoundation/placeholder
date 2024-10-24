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

#include <ostream>

#include <type_traits>

#include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"
#include "nil/crypto3/multiprecision/big_integer/modular/modular_functions.hpp"

namespace nil::crypto3::multiprecision::detail {
    // TODO(ioxid): merge with modular_functions
    // fixed precision modular params type which supports compile-time execution
    template<typename big_integer_t>
    class modular_ops {
      private:
        using modular_functions_t = modular_functions<big_integer_t>;

      public:
        using policy_type = typename modular_functions_t::policy_type;

        using big_integer_doubled_limbs = typename policy_type::big_integer_doubled_limbs;
        // using big_integer_t = typename policy_type::big_integer_t;

        constexpr modular_ops(const big_integer_t &m)
            : m_modular_functions(m), m_use_montgomery_form(check_montgomery_constraints(m)) {}

      private:
        constexpr auto &get_modular_functions() { return m_modular_functions; }
        constexpr const auto &get_modular_functions() const { return m_modular_functions; }

        constexpr bool is_montgomery_form() const { return m_use_montgomery_form; }

      public:
        constexpr const auto &get_mod() const { return m_modular_functions.get_mod(); }

        template<unsigned Bits1>
        constexpr void reduce(big_integer<Bits1> &result) const {
            if (m_use_montgomery_form) {
                m_modular_functions.montgomery_reduce(result);
            } else {
                m_modular_functions.barrett_reduce(result);
            }
        }

        constexpr void adjust_modular(big_integer_t &result) const {
            adjust_modular(result, result);
        }

        template<unsigned Bits2>
        constexpr void adjust_modular(big_integer_t &result,
                                      const big_integer<Bits2> &input) const {
            big_integer_doubled_limbs tmp;
            m_modular_functions.barrett_reduce(tmp, input);
            if (m_use_montgomery_form) {
                //
                // to prevent problems with trivial cpp_int
                //
                big_integer_doubled_limbs r2(m_modular_functions.get_r2());

                tmp *= r2;
                m_modular_functions.montgomery_reduce(tmp);
            }
            result = tmp;
        }

        [[nodiscard]] constexpr big_integer_t adjusted_regular(const big_integer_t &a) const {
            big_integer_t result;
            adjust_regular(result, a);
            return result;
        }

        template<unsigned Bits1, unsigned Bits2,
                 /// input number should fit in result
                 std::enable_if_t<Bits1 >= Bits2, int> = 0>
        constexpr void adjust_regular(big_integer<Bits1> &result,
                                      const big_integer<Bits2> &input) const {
            result = input;
            if (m_use_montgomery_form) {
                m_modular_functions.montgomery_reduce(result);
            }
        }

        template<typename big_integer_t1, typename T>
        constexpr void exp(big_integer_t1 &result, const T &exp) const {
            exp(result, result, exp);
        }

        template<typename big_integer_t1, typename big_integer_t2, typename T>
        constexpr void exp(big_integer_t1 &result, const big_integer_t2 &a, const T &exp) const {
            if (m_use_montgomery_form) {
                m_modular_functions.montgomery_exp(result, a, exp);
            } else {
                m_modular_functions.regular_exp(result, a, exp);
            }
        }

        template<typename big_integer_t1>
        constexpr void mul(big_integer_t1 &result, const big_integer_t1 &y) const {
            if (m_use_montgomery_form) {
                m_modular_functions.montgomery_mul(result, y);
            } else {
                m_modular_functions.regular_mul(result, y);
            }
        }

        template<typename big_integer_t1, typename big_integer_t2>
        constexpr void add(big_integer_t1 &result, const big_integer_t2 &y) const {
            m_modular_functions.regular_add(result, y);
        }

        template<typename big_integer_t1>
        constexpr operator big_integer_t1() {
            return get_mod();
        };

        constexpr bool compare_eq(const modular_ops &o) const { return get_mod() == o.get_mod(); }

        constexpr void swap(modular_ops &o) noexcept {
            m_modular_functions.swap(o.get_modular_functions());
            bool t = m_use_montgomery_form;
            m_use_montgomery_form = o.m_use_montgomery_form;
            o.m_use_montgomery_form = t;
        }

        // TODO: check function correctness
        constexpr friend std::ostream &operator<<(std::ostream &o, const modular_ops &a) {
            o << a.get_mod();
            return o;
        }

      private:
        modular_functions_t m_modular_functions;
        bool m_use_montgomery_form = false;
    };

    template<typename big_integer_t, const big_integer_t &Modulus>
    class modular_ops_storage_ct {
      public:
        using modular_ops_t = modular_ops<big_integer_t>;

        constexpr modular_ops_storage_ct() {}

        static constexpr const modular_ops_t &ops() { return m_modular_ops; }

      private:
        static constexpr modular_ops_t m_modular_ops{Modulus};
    };

    // Must be used only in the tests, we must normally use only modular_ops_storage_ct.
    template<typename big_integer_t>
    class modular_ops_storage_rt {
      public:
        using modular_ops_t = modular_ops<big_integer_t>;

        constexpr modular_ops_storage_rt(const big_integer_t &input) : m_modular_ops(input) {}

        constexpr const modular_ops_t &ops() const { return m_modular_ops; }

      private:
        modular_ops_t m_modular_ops;
    };
}  // namespace nil::crypto3::multiprecision
