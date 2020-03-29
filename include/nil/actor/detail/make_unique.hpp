//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <memory>

namespace nil::actor::detail {

    template<class T, class... Ts>
    std::unique_ptr<T> make_unique(Ts &&... xs) {
        return std::unique_ptr<T> {new T(std::forward<Ts>(xs)...)};
    }

}    // namespace nil::actor::detail