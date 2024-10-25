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

#include <type_traits>
namespace nil::crypto3::multiprecision::detail {
    template<const auto &Modulus, template<typename> typename modular_ops_template>
    class modular_ops_storage_ct {
      public:
        using big_integer_t = std::decay_t<decltype(Modulus)>;
        using modular_ops_t = modular_ops_template<big_integer_t>;

        constexpr modular_ops_storage_ct() {}

        static constexpr const modular_ops_t &ops() { return m_modular_ops; }

      private:
        static constexpr modular_ops_t m_modular_ops{Modulus};
    };

    template<typename big_integer_t_, template<typename> typename modular_ops_template>
    class modular_ops_storage_rt {
      public:
        using big_integer_t = big_integer_t_;
        using modular_ops_t = modular_ops_template<big_integer_t>;

        constexpr modular_ops_storage_rt(const big_integer_t &input) : m_modular_ops(input) {}

        constexpr const modular_ops_t &ops() const { return m_modular_ops; }

      private:
        modular_ops_t m_modular_ops;
    };
}  // namespace nil::crypto3::multiprecision::detail
