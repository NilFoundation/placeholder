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

#include <cstdint>
#include <typeinfo>
#include <functional>

#include <nil/actor/type_erased_value.hpp>

#include <nil/actor/detail/type_erased_value_impl.hpp>

namespace nil {
    namespace actor {

        /// @relates type_erased_value
        /// Creates a type-erased value of type `T` from `xs`.
        template<class T, class... Ts>
        type_erased_value_ptr make_type_erased_value(Ts &&... xs) {
            type_erased_value_ptr result;
            result.reset(new detail::type_erased_value_impl<T>(std::forward<Ts>(xs)...));
            return result;
        }

        /// @relates type_erased_value
        /// Converts values to type-erased values.
        struct type_erased_value_factory {
            template<class T>
            type_erased_value_ptr operator()(T &&x) const {
                return make_type_erased_value<typename std::decay<T>::type>(std::forward<T>(x));
            }
        };

    }    // namespace actor
}    // namespace nil
