//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE and LICENSE_ALTERNATIVE.
//---------------------------------------------------------------------------//

#pragma once

#include <cstdint>
#include <type_traits>
#include <typeinfo>
#include <utility>

#include <nil/actor/type_nr.hpp>

namespace nil {
    namespace actor {

        /// Bundles the type number with its C++ `type_info` object. The type number is
        /// non-zero for builtin types and the pointer to the `type_info` object is
        /// non-null for custom types.
        using rtti_pair = std::pair<uint16_t, const std::type_info *>;

        /// @relates rtti_pair
        template<class T>
        typename std::enable_if<type_nr<T>::value == 0, rtti_pair>::type make_rtti_pair() {
            return {0, &typeid(T)};
        }

        /// @relates rtti_pair
        template<class T>
        typename std::enable_if<type_nr<T>::value != 0, rtti_pair>::type make_rtti_pair() {
            auto n = type_nr<T>::value;
            return {n, nullptr};
        }

        /// @relates rtti_pair
        std::string to_string(rtti_pair x);

    }    // namespace actor
}    // namespace nil
