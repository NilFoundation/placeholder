//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE and LICENSE_ALTERNATIVE.
//---------------------------------------------------------------------------//

#include <cstdint>
#include <type_traits>

#include <nil/actor/detail/type_traits.hpp>

#pragma once

namespace nil {
    namespace actor {

        /// A C++11/14 drop-in replacement for C++17's `std::byte`.
        typedef std::uint8_t byte;

        template<class IntegerType, class = detail::enable_if_tt<std::is_integral<IntegerType>>>
        constexpr IntegerType to_integer(byte x) noexcept {
            return static_cast<IntegerType>(x);
        }
    }    // namespace actor
}    // namespace nil
