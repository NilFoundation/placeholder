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

#include <memory>

namespace nil {
    namespace actor {
        namespace detail {

            template<class T, class... Ts>
            std::unique_ptr<T> make_unique(Ts &&... xs) {
                return std::unique_ptr<T> {new T(std::forward<Ts>(xs)...)};
            }

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
