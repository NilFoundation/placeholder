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

#include <nil/actor/deep_to_string.hpp>
#include <nil/actor/timestamp.hpp>

namespace nil {
    namespace actor {

        timestamp make_timestamp() {
            return std::chrono::system_clock::now();
        }

        std::string timestamp_to_string(timestamp x) {
            return deep_to_string(x.time_since_epoch().count());
        }

        void append_timestamp_to_string(std::string &x, timestamp y) {
            x += timestamp_to_string(y);
        }

    }    // namespace actor
}    // namespace nil
