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

#include <type_traits>

#include <nil/actor/memory_managed.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            class disposer {
            public:
                inline void operator()(memory_managed *ptr) const noexcept {
                    ptr->request_deletion(false);
                }

                template<class T>
                typename std::enable_if<!std::is_base_of<memory_managed, T>::value>::type operator()(T *ptr) const
                    noexcept {
                    delete ptr;
                }
            };

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
