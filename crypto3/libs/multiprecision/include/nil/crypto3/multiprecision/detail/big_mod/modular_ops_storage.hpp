//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2024-2025 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

namespace nil::crypto3::multiprecision::detail {
    // Compile-time storage for modular arithmetic operations. Stores them in a constexpr
    // variable.
    template<const auto &Modulus, typename modular_ops_t_>
    class modular_ops_storage_ct {
      public:
        using modular_ops_t = modular_ops_t_;

        constexpr modular_ops_storage_ct() {}

        static constexpr const modular_ops_t &ops() { return m_modular_ops; }

        static constexpr bool compare_eq(const modular_ops_storage_ct & /*other*/) {
            return true;
        }

      private:
        static constexpr modular_ops_t m_modular_ops{Modulus};
    };

    // Compile-time storage for modular arithmetic operations without modulus parameter.
    // Stores them in a constexpr variable.
    template<typename modular_ops_t_>
    class modular_ops_storage_fixed_ct {
      public:
        using modular_ops_t = modular_ops_t_;

        constexpr modular_ops_storage_fixed_ct() {}

        static constexpr const modular_ops_t &ops() { return m_modular_ops; }

        static constexpr bool compare_eq(const modular_ops_storage_fixed_ct & /*other*/) {
            return true;
        }

      private:
        static constexpr modular_ops_t m_modular_ops{};
    };

    // Runtime storage for modular arithmetic operations. Stores them in a plain variable
    // constructed at runtime.
    template<typename modular_ops_t_>
    class modular_ops_storage_rt {
      public:
        using modular_ops_t = modular_ops_t_;

        constexpr modular_ops_storage_rt(const typename modular_ops_t::base_type &input)
            : m_modular_ops(input) {}

        constexpr const modular_ops_t &ops() const { return m_modular_ops; }

        constexpr bool compare_eq(const modular_ops_storage_rt &other) const {
            return m_modular_ops.compare_eq(other.m_modular_ops);
        }

      private:
        modular_ops_t m_modular_ops;
    };
}  // namespace nil::crypto3::multiprecision::detail
