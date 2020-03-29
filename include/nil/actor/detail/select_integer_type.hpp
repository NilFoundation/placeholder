//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <cstdint>

namespace nil::actor::detail {

    template<int, bool>
    struct select_integer_type;

    template<>
    struct select_integer_type<1, true> {
        using type = int8_t;
    };

    template<>
    struct select_integer_type<1, false> {
        using type = uint8_t;
    };

    template<>
    struct select_integer_type<2, true> {
        using type = int16_t;
    };

    template<>
    struct select_integer_type<2, false> {
        using type = uint16_t;
    };

    template<>
    struct select_integer_type<4, true> {
        using type = int32_t;
    };

    template<>
    struct select_integer_type<4, false> {
        using type = uint32_t;
    };

    template<>
    struct select_integer_type<8, true> {
        using type = int64_t;
    };

    template<>
    struct select_integer_type<8, false> {
        using type = uint64_t;
    };

    template<int Size, bool IsSigned>
    using select_integer_type_t = typename select_integer_type<Size, IsSigned>::type;

}    // namespace nil::actor::detail