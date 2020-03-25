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

#include <nil/actor/catch_all.hpp>
#include <nil/actor/timeout_definition.hpp>

namespace nil {
    namespace actor {

        template<class T>
        struct is_timeout_or_catch_all : std::false_type {};

        template<class T>
        struct is_timeout_or_catch_all<catch_all<T>> : std::true_type {};

        template<class T>
        struct is_timeout_or_catch_all<timeout_definition<T>> : std::true_type {};

    }    // namespace actor
}    // namespace nil
