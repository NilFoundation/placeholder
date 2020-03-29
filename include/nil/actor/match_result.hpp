//---------------------------------------------------------------------------//
// Copyright (c) 2011-2020 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <string>

#include <boost/config.hpp>

namespace nil {
    namespace actor {

        /// Denotes the invoke result of a ::behavior or ::message_handler.
        enum class match_result {
            no_match,
            match,
            skip,
        };

        /// @relates match_result
        BOOST_SYMBOL_VISIBLE std::string to_string(match_result);

    }    // namespace actor
}    // namespace nil
