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

#include <tuple>
#include <cstddef>
#include <cstdint>
#include <typeinfo>

#include <nil/actor/type_erased_tuple.hpp>

#include <nil/actor/detail/type_erased_tuple_view.hpp>

namespace nil {
    namespace actor {

        /// @relates type_erased_tuple
        template<class... Ts>
        detail::type_erased_tuple_view<Ts...> make_type_erased_tuple_view(Ts &... xs) {
            return {xs...};
        }

    }    // namespace actor
}    // namespace nil
