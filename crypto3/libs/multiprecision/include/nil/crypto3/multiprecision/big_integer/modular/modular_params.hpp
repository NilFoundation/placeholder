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

#include <boost/lexical_cast.hpp>

#include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"
#include "nil/crypto3/multiprecision/big_integer/modular/modular_functions.hpp"

namespace nil::crypto3::multiprecision {
    // TODO(ioxid): merge with modular_functions
    // fixed precision modular params type which supports compile-time execution
    template<typename big_integer_t>
    class modular_params {
      protected:
        using modular_functions_t = modular_functions<big_integer_t>;

      public:
        using policy_type = typename modular_functions_t::policy_type;

        using Backend_doubled_limbs = typename policy_type::Backend_doubled_limbs;
        // using big_integer_t = typename policy_type::big_integer_t;

        constexpr auto &get_modular_functions() { return m_modular_functions; }
        constexpr const auto &get_modular_functions() const { return m_modular_functions; }

        constexpr auto &get_is_odd_mod() { return is_odd_mod; }
        constexpr const auto &get_is_odd_mod() const { return is_odd_mod; }

        constexpr auto get_mod() const { return m_modular_functions.get_mod(); }

        constexpr modular_params() {}

        constexpr modular_params(const big_integer_t &m) : m_modular_functions(m) {
            using boost::multiprecision::default_ops::eval_bit_test;
            is_odd_mod = eval_bit_test(m, 0);
        }

        constexpr modular_params(const modular_params &o)
            : m_modular_functions(o.get_modular_functions()) {
            is_odd_mod = o.get_is_odd_mod();
        }

        template<unsigned Bits1>
        constexpr void reduce(big_integer<Bits1> &result) const {
            if (is_odd_mod) {
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
            Backend_doubled_limbs tmp;
            m_modular_functions.barrett_reduce(tmp, input);
            if (is_odd_mod) {
                //
                // to prevent problems with trivial cpp_int
                //
                Backend_doubled_limbs r2(m_modular_functions.get_r2());

                eval_multiply(tmp, r2);
                m_modular_functions.montgomery_reduce(tmp);
            }
            result = tmp;
        }

        template<unsigned Bits1, unsigned Bits2,
                 /// input number should fit in result
                 typename = typename boost::enable_if_c<Bits1 >= Bits2>::type>
        constexpr void adjust_regular(big_integer<Bits1> &result,
                                      const big_integer<Bits2> &input) const {
            result = input;
            if (is_odd_mod) {
                m_modular_functions.montgomery_reduce(result);
            }
        }

        template<typename Backend1, typename T>
        constexpr void mod_exp(Backend1 &result, const T &exp) const {
            mod_exp(result, result, exp);
        }

        template<typename Backend1, typename Backend2, typename T>
        constexpr void mod_exp(Backend1 &result, const Backend2 &a, const T &exp) const {
            if (is_odd_mod) {
                m_modular_functions.montgomery_exp(result, a, exp);
            } else {
                m_modular_functions.regular_exp(result, a, exp);
            }
        }

        template<typename Backend1>
        constexpr void mod_mul(Backend1 &result, const Backend1 &y) const {
            if (is_odd_mod) {
                m_modular_functions.montgomery_mul(result, y);
            } else {
                m_modular_functions.regular_mul(result, y);
            }
        }

        template<typename Backend1, typename Backend2>
        constexpr void mod_add(Backend1 &result, const Backend2 &y) const {
            m_modular_functions.regular_add(result, y);
        }

        template<typename Backend1>
        constexpr operator Backend1() {
            return get_mod();
        };

        constexpr bool compare_eq(const modular_params &o) const {
            // They are either equal or not:
            return get_mod().compare(o.get_mod()) == 0;
        }

        constexpr void swap(modular_params &o) noexcept {
            m_modular_functions.swap(o.get_modular_functions());
            bool t = is_odd_mod;
            is_odd_mod = o.get_is_odd_mod();
            o.get_is_odd_mod() = t;
        }

        constexpr modular_params &operator=(const modular_params &o) {
            m_modular_functions = o.get_modular_functions();
            is_odd_mod = o.get_is_odd_mod();
            return *this;
        }

        constexpr modular_params &operator=(const big_integer_t &m) {
            m_modular_functions = m;
            is_odd_mod = boost::multiprecision::default_ops::eval_bit_test(m, 0);
            return *this;
        }

        // TODO: check function correctness
        constexpr friend std::ostream &operator<<(std::ostream &o, const modular_params &a) {
            o << a.get_mod();
            return o;
        }

      protected:
        modular_functions_t m_modular_functions;
        bool is_odd_mod = false;
    };

    template<typename big_integer_t, const big_integer_t &Modulus>
    class modular_params_storage_ct {
      public:
        using modular_params_t = modular_params<big_integer_t>;

        constexpr modular_params_storage_ct() {}

        constexpr modular_params_storage_ct(modular_params_t &input) {}

        constexpr void set_modular_params(const modular_params_t &input) {}

        template<typename T>
        constexpr void set_modular_params(const T &input) {}

        constexpr const modular_params_t &modular_params() const { return m_mod; }

      protected:
        constexpr static const modular_params_t m_mod{Modulus};
    };

    // Must be used only in the tests, we must normally use only modular_params_storage_ct.
    template<typename big_integer_t>
    class modular_params_storage_rt {
      public:
        using modular_params_t = modular_params<big_integer_t>;

        constexpr modular_params_storage_rt() {}

        constexpr modular_params_storage_rt(modular_params_t input) : m_mod(input) {}

        constexpr void set_modular_params(const modular_params_t &input) { m_mod = input; }

        constexpr void set_modular_params(const big_integer_t &input) { m_mod = input; }

        constexpr modular_params_t &modular_params() { return m_mod; }
        constexpr const modular_params_t &modular_params() const { return m_mod; }

        modular_params_t m_mod;
    };
}  // namespace nil::crypto3::multiprecision
