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

#include <nil/actor/stream_priority.hpp>

namespace nil {
    namespace actor {

        std::string to_string(stream_priority x) {
            switch (x) {
                default:
                    return "invalid";
                case stream_priority::very_high:
                    return "very_high";
                case stream_priority::high:
                    return "high";
                case stream_priority::normal:
                    return "normal";
                case stream_priority::low:
                    return "low";
                case stream_priority::very_low:
                    return "very_low";
            }
        }

    }    // namespace actor
}    // namespace nil
