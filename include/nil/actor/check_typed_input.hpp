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

#include <nil/actor/fwd.hpp>
#include <nil/actor/replies_to.hpp>

#include <nil/actor/detail/type_list.hpp>

namespace nil {
    namespace actor {

        template<class T>
        struct output_types_of {
            // nop
        };

        template<class In, class Out>
        struct output_types_of<typed_mpi<In, Out>> {
            using type = Out;
        };

        template<class T>
        struct signatures_of {
            using type = typename std::remove_pointer<T>::type::signatures;
        };

        template<class T>
        using signatures_of_t = typename signatures_of<T>::type;

        template<class T>
        constexpr bool statically_typed() {
            return !std::is_same<none_t, typename std::remove_pointer<T>::type::signatures>::value;
        }

        template<class T>
        struct is_void_response : std::false_type {};

        template<>
        struct is_void_response<detail::type_list<void>> : std::true_type {};

        // true for the purpose of type checking performed by send()
        template<>
        struct is_void_response<none_t> : std::true_type {};

    }    // namespace actor
}    // namespace nil
