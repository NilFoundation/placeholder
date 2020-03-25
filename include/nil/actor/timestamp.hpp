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

#include <chrono>
#include <string>
#include <cstdint>

#include <nil/actor/timespan.hpp>

namespace nil {
    namespace actor {

        /// A portable timestamp with nanosecond resolution anchored at the UNIX epoch.
        using timestamp = std::chrono::time_point<std::chrono::system_clock, timespan>;

        /// Convenience function for returning a `timestamp` representing
        /// the current system time.
        timestamp make_timestamp();

        /// Prints `x` in ISO 8601 format, e.g., `2018-11-15T06:25:01.462`.
        std::string timestamp_to_string(timestamp x);

        /// Appends the timestamp `x` in ISO 8601 format, e.g.,
        /// `2018-11-15T06:25:01.462`, to `y`.
        void append_timestamp_to_string(std::string &x, timestamp y);

    }    // namespace actor
}    // namespace nil
