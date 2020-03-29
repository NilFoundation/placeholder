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

#include <boost/config.hpp>

namespace nil {
    namespace actor {

        /// Categorizes individual streams.
        enum class stream_priority {
            /// Denotes soft-realtime traffic.
            very_high,
            /// Denotes time-sensitive traffic.
            high,
            /// Denotes traffic with moderate timing requirements.
            normal,
            /// Denotes uncritical traffic without timing requirements.
            low,
            /// Denotes best-effort traffic.
            very_low
        };

        /// Stores the number of `stream_priority` classes.
        static constexpr size_t stream_priorities = 5;

        BOOST_SYMBOL_VISIBLE std::string to_string(stream_priority x);

    }    // namespace actor
}    // namespace nil
