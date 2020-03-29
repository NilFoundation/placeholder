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

#include <cstdint>
#include <string>
#include <type_traits>

#include <boost/config.hpp>

namespace nil {
    namespace actor {

        enum class message_priority {
            high = 0,
            normal = 1,
        };

        using high_message_priority_constant = std::integral_constant<message_priority, message_priority::high>;

        using normal_message_priority_constant = std::integral_constant<message_priority, message_priority::normal>;

        BOOST_SYMBOL_VISIBLE std::string to_string(message_priority);

    }    // namespace actor
}    // namespace nil
