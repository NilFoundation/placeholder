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

// IWYU pragma: private

#include <cstddef>
#include <type_traits>

#include "nil/crypto3/multiprecision/big_uint_impl.hpp"

namespace nil::crypto3::multiprecision::detail {
    // Compile-time storage for modular arithmetic operations. Stores them in a constexpr variable.
    template<const auto &Modulus, template<std::size_t> typename modular_ops_template>
    class modular_ops_storage_ct {
      public:
        using big_uint_t = std::decay_t<decltype(Modulus)>;
        static constexpr std::size_t Bits = big_uint_t::Bits;
        using modular_ops_t = modular_ops_template<Bits>;

        static_assert(Bits == Modulus.msb() + 1, "modulus bit width should match used precision");

        constexpr modular_ops_storage_ct() {}

        static constexpr const modular_ops_t &ops() { return m_modular_ops; }

      private:
        static constexpr modular_ops_t m_modular_ops{Modulus};
    };

    // Runtime storage for modular arithmetic operations. Stores them in a plain variable
    // constructed at runtime.
    template<std::size_t Bits, template<std::size_t> typename modular_ops_template>
    class modular_ops_storage_rt {
      public:
        using big_uint_t = big_uint<Bits>;
        using modular_ops_t = modular_ops_template<Bits>;

        constexpr modular_ops_storage_rt(const big_uint_t &input) : m_modular_ops(input) {}

        constexpr const modular_ops_t &ops() const { return m_modular_ops; }

      private:
        modular_ops_t m_modular_ops;
    };
}  // namespace nil::crypto3::multiprecision::detail
