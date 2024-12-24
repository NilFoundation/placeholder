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

#include <cstddef>

namespace nil::crypto3::multiprecision::detail {
    template<std::size_t Bits>
    struct modular_policy;

    template<std::size_t Bits_>
    class barrett_modular_ops;

    template<std::size_t Bits_>
    class montgomery_modular_ops;
}  // namespace nil::crypto3::multiprecision::detail
