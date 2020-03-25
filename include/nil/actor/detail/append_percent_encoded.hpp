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

#include <nil/actor/fwd.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            // Escapes all reserved characters according to RFC 3986 in `x` and
            // adds the encoded string to `str`.
            void append_percent_encoded(std::string &str, string_view x, bool is_path = false);

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
