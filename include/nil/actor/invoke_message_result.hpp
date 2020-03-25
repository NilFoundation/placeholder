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

#include <string>

namespace nil {
    namespace actor {

        enum invoke_message_result { im_success, im_skipped, im_dropped };

        inline std::string to_string(invoke_message_result x) {
            return x == im_success ? "im_success" : (x == im_skipped ? "im_skipped" : "im_dropped");
        }

    }    // namespace actor
}    // namespace nil
