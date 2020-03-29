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

namespace nil::actor::detail::parser {

    /// Returns whether `c` equals `C`.
    template<char C>
    bool is_char(char c) {
        return c == C;
    }

    /// Returns whether `c` equals `C` (case insensitive).
    template<char C>
    bool is_ichar(char c) {
        static_assert(C >= 'a' && C <= 'z', "Expected a-z (lowercase).");
        return c == C || c == (C - 32);
    }

}    // namespace nil::actor::detail::parser
