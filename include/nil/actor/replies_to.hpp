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

#include <string>

#include <nil/actor/illegal_message_element.hpp>
#include <nil/actor/output_stream.hpp>
#include <nil/actor/stream.hpp>

#include <nil/actor/detail/type_list.hpp>
#include <nil/actor/detail/type_pair.hpp>
#include <nil/actor/detail/type_traits.hpp>

namespace nil {
    namespace actor {

        /// @cond PRIVATE
        std::string replies_to_type_name(size_t input_size,
                                         const std::string *input,
                                         size_t output_opt1_size,
                                         const std::string *output_opt1);
        /// @endcond

        template<class...>
        struct output_tuple {};

        template<class Input, class Output>
        struct typed_mpi {};

        template<class... Is>
        struct replies_to {
            template<class... Os>
            using with = typed_mpi<detail::type_list<Is...>, output_tuple<Os...>>;

            /// @private
            template<class O, class... Os>
            using with_stream = typed_mpi<detail::type_list<Is...>, output_stream<O, Os...>>;
        };

        template<class... Is>
        using reacts_to = typed_mpi<detail::type_list<Is...>, output_tuple<void>>;

    }    // namespace actor
}    // namespace nil
