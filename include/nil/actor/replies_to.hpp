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

#include <string>

#include <nil/actor/detail/type_list.hpp>

namespace nil {
    namespace actor {

        /// @cond PRIVATE
        BOOST_SYMBOL_VISIBLE std::string replies_to_type_name(size_t input_size, const std::string *input,
                                                              size_t output_size, const std::string *output);
        /// @endcond

        template<class...>
        struct output_tuple {};

        template<class Input, class Output>
        struct typed_mpi {};

        template<class... Is>
        struct replies_to {
            template<class... Os>
            using with = typed_mpi<detail::type_list<Is...>, output_tuple<Os...>>;
        };

        template<class... Is>
        using reacts_to = typed_mpi<detail::type_list<Is...>, output_tuple<void>>;

    }    // namespace actor
}    // namespace nil
