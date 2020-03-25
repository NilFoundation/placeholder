//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#pragma once

#include <new>
#include <cstdint>
#include <typeinfo>
#include <stdexcept>
#include <type_traits>

#include <nil/actor/atom.hpp>
#include <nil/actor/none.hpp>
#include <nil/actor/variant.hpp>

namespace nil {
    namespace actor {

        using primitive_variant =
            variant<int8_t, int16_t, int32_t, int64_t, uint8_t, uint16_t, uint32_t, uint64_t, float, double,
                    long double, std::string, std::u16string, std::u32string, atom_value, bool>;

    }
}    // namespace nil
