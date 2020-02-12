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

#include <sstream>

#include <nil/actor/duration.hpp>

#include <nil/actor/detail/enum_to_string.hpp>

namespace nil {
    namespace actor {

        namespace {

            const char *time_unit_strings[] = {"invalid",      "minutes",      "seconds",
                                               "milliseconds", "microseconds", "nanoseconds"};

            const char *time_unit_short_strings[] = {"?", "min", "s", "ms", "us", "ns"};

        }    // namespace

        std::string to_string(time_unit x) {
            return detail::enum_to_string(x, time_unit_strings);
        }

        std::string to_string(const duration &x) {
            if (x.unit == time_unit::invalid)
                return "infinite";
            auto result = std::to_string(x.count);
            result += detail::enum_to_string(x.unit, time_unit_short_strings);
            return result;
        }

        bool operator==(const duration &lhs, const duration &rhs) {
            return lhs.unit == rhs.unit && lhs.count == rhs.count;
        }

    }    // namespace actor
}    // namespace nil
