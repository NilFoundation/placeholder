//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <type_traits>

#include <nil/actor/detail/type_traits.hpp>
#include <nil/actor/intrusive_ptr.hpp>
#include <nil/actor/ref_counted.hpp>

namespace nil::actor {

    /// Constructs an object of type `T` in an `intrusive_ptr`.
    /// @relates ref_counted
    template<class T, class... Ts>
    intrusive_ptr<T> make_counted(Ts &&... xs) {
        return intrusive_ptr<T>(new T(std::forward<Ts>(xs)...), false);
    }

}    // namespace nil::actor
