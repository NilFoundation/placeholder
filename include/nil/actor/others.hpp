//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#pragma once

#include <functional>
#include <type_traits>

#include <nil/actor/catch_all.hpp>

namespace nil {
    namespace actor {

        struct others_t {
            constexpr others_t() {
                // nop
            }

            template<class F>
            catch_all<F> operator>>(F fun) const {
                return {fun};
            }
        };

        constexpr others_t others = others_t {};

    }    // namespace actor
}    // namespace nil
