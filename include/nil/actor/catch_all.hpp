//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt or
// http://opensource.org/licenses/BSD-3-Clause
//---------------------------------------------------------------------------//

#pragma once

#include <functional>
#include <type_traits>

#include <nil/actor/result.hpp>
#include <nil/actor/message.hpp>
#include <nil/actor/message_view.hpp>

namespace nil {
    namespace actor {

        template<class F>
        struct catch_all {
            using fun_type = std::function<result<message>(message_view &)>;

            F handler;

            catch_all(catch_all &&x) : handler(std::move(x.handler)) {
                // nop
            }

            template<class T>
            catch_all(T &&x) : handler(std::forward<T>(x)) {
                // nop
            }

            static_assert(std::is_convertible<F, fun_type>::value,
                          "catch-all handler must have signature "
                          "result<message> (message_view&)");

            fun_type lift() const {
                return handler;
            }
        };

        template<class T>
        struct is_catch_all : std::false_type {};

        template<class T>
        struct is_catch_all<catch_all<T>> : std::true_type {};

    }    // namespace actor
}    // namespace nil
