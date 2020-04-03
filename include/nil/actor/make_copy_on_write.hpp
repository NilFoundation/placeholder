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

#include <nil/actor/intrusive_cow_ptr.hpp>

namespace nil {
    namespace actor {

        /// Constructs an object of type `T` in an `intrusive_cow_ptr`.
        /// @relates ref_counted
        /// @relatealso intrusive_cow_ptr
        template<class T, class... Ts>
        intrusive_cow_ptr<T> make_copy_on_write(Ts &&... xs) {
            return intrusive_cow_ptr<T>(new T(std::forward<Ts>(xs)...), false);
        }

    }    // namespace actor
}    // namespace nil
